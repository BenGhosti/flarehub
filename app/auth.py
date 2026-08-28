"""
FlareHub – authentication: PIN + WebAuthn/Passkey.
Behavior is fully controlled by AUTH_MODE in the .env (pin | passkey | both | none).
"""
import hashlib
import hmac
import json
import time
from datetime import datetime

import bcrypt
from fastapi import Request, HTTPException
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from sqlalchemy.orm import Session
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.parse_authentication_credential_json import (
    parse_authentication_credential_json,
)
from webauthn.helpers.parse_registration_credential_json import (
    parse_registration_credential_json,
)
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
)

from app.config import settings
from app.database import WebAuthnCredential

serializer = URLSafeTimedSerializer(settings.SESSION_SECRET_KEY, salt="flarehub-session")

# In-memory challenge store (short-lived, no persistence needed)
_pending_challenges: dict = {}
# In-memory PIN lockout tracking per IP
_pin_failures: dict = {}


# ---------------------------------------------------------------------------
# Stateless access token (no session cookie!)
#
# Security model: after PIN/passkey login, the frontend receives a short-lived,
# signed token and stores it ONLY in the sessionStorage (per browser session).
# There are no cookies – on every new browser visit the token is gone and the
# user must log in again with PIN or passkey.
# ---------------------------------------------------------------------------
def create_access_token() -> str:
    return serializer.dumps({"authenticated": True, "ts": time.time()})


def verify_access_token(token: str) -> bool:
    try:
        data = serializer.loads(token, max_age=settings.SESSION_EXPIRY_HOURS * 3600)
        return bool(data.get("authenticated"))
    except (BadSignature, SignatureExpired):
        return False


def extract_bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if header.startswith("Bearer "):
        return header[7:].strip()
    return None


def get_current_session(request: Request) -> bool:
    """Dependency: checks the Bearer token from the Authorization header.
    Always True when AUTH_MODE=none."""
    if settings.auth_disabled:
        return True
    token = extract_bearer_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if not verify_access_token(token):
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    return True


# ---------------------------------------------------------------------------
# PIN
# ---------------------------------------------------------------------------
def _is_locked_out(ip: str) -> tuple[bool, int]:
    entry = _pin_failures.get(ip)
    if not entry:
        return False, 0
    count, first_fail_ts = entry
    if count < settings.AUTH_PIN_MAX_ATTEMPTS:
        return False, 0
    elapsed = time.time() - first_fail_ts
    remaining = settings.AUTH_PIN_LOCKOUT_SECONDS - elapsed
    if remaining <= 0:
        _pin_failures.pop(ip, None)
        return False, 0
    return True, int(remaining)


def _register_pin_failure(ip: str):
    count, first_ts = _pin_failures.get(ip, (0, time.time()))
    _pin_failures[ip] = (count + 1, first_ts)


def _clear_pin_failures(ip: str):
    _pin_failures.pop(ip, None)


def verify_pin(pin: str, client_ip: str) -> tuple[bool, str]:
    if not settings.auth_pin_enabled:
        return False, "PIN login is disabled"

    locked, remaining = _is_locked_out(client_ip)
    if locked:
        return False, f"Too many failed attempts. Try again in {remaining}s"

    if not settings.AUTH_PIN_HASH:
        return False, "No PIN configured (set AUTH_PIN or AUTH_PIN_HASH in .env)"

    try:
        valid = bcrypt.checkpw(pin.encode(), settings.AUTH_PIN_HASH.encode())
    except ValueError:
        valid = False

    if valid:
        _clear_pin_failures(client_ip)
        return True, "OK"
    else:
        _register_pin_failure(client_ip)
        return False, "Incorrect PIN"


# ---------------------------------------------------------------------------
# Admin token (passkey management)
# ---------------------------------------------------------------------------
# In-memory lockout tracking for admin token attempts, per IP (similar to PIN lockout)
_admin_token_failures: dict = {}


def _admin_locked_out(ip: str) -> tuple[bool, int]:
    entry = _admin_token_failures.get(ip)
    if not entry:
        return False, 0
    count, first_fail_ts = entry
    if count < settings.AUTH_PIN_MAX_ATTEMPTS:
        return False, 0
    elapsed = time.time() - first_fail_ts
    remaining = settings.AUTH_PIN_LOCKOUT_SECONDS - elapsed
    if remaining <= 0:
        _admin_token_failures.pop(ip, None)
        return False, 0
    return True, int(remaining)


def verify_admin_token(token: str, client_ip: str) -> tuple[bool, str]:
    """Checks the admin token from the .env. Intended as a separate hurdle from the
    normal login: it additionally protects passkey management, even with an active session."""
    if not settings.ADMIN_TOKEN:
        return False, "No admin token configured (set ADMIN_TOKEN in .env)"

    locked, remaining = _admin_locked_out(client_ip)
    if locked:
        return False, f"Too many failed attempts. Try again in {remaining}s"

    if not token:
        return False, "Admin token required"

    valid = hmac.compare_digest(token, settings.ADMIN_TOKEN)

    if valid:
        _admin_token_failures.pop(client_ip, None)
        return True, "OK"
    else:
        count, first_ts = _admin_token_failures.get(client_ip, (0, time.time()))
        _admin_token_failures[client_ip] = (count + 1, first_ts)
        return False, "Invalid admin token"


def create_admin_token_grant() -> str:
    """Short-lived, signed token issued after a successful admin token entry that
    unlocks the passkey management endpoints for a short time."""
    return serializer.dumps({"admin_grant": True, "ts": time.time()})


def verify_admin_token_grant(grant: str, max_age_seconds: int = 600) -> bool:
    try:
        data = serializer.loads(grant, max_age=max_age_seconds)
        return bool(data.get("admin_grant"))
    except (BadSignature, SignatureExpired):
        return False


# ---------------------------------------------------------------------------
# WebAuthn / Passkey
# ---------------------------------------------------------------------------
def _attachment():
    val = settings.WEBAUTHN_AUTHENTICATOR_ATTACHMENT.strip().lower()
    if val == "platform":
        return AuthenticatorAttachment.PLATFORM
    if val == "cross-platform":
        return AuthenticatorAttachment.CROSS_PLATFORM
    return None


def _user_verification():
    mapping = {
        "required": UserVerificationRequirement.REQUIRED,
        "preferred": UserVerificationRequirement.PREFERRED,
        "discouraged": UserVerificationRequirement.DISCOURAGED,
    }
    return mapping.get(settings.WEBAUTHN_USER_VERIFICATION.lower(), UserVerificationRequirement.PREFERRED)


def _user_handle() -> bytes:
    """Stable user handle for the single admin account.

    Derive it deterministically from SESSION_SECRET_KEY so that all registered
    passkeys share the same user handle and no randomly changing ID is created."""
    return hashlib.sha256(settings.SESSION_SECRET_KEY.encode()).digest()[:32]


def _require_user_verification() -> bool:
    return settings.WEBAUTHN_USER_VERIFICATION.strip().lower() == "required"


def build_registration_options(db: Session, username: str = "admin"):
    existing = db.query(WebAuthnCredential).all()
    exclude = [
        PublicKeyCredentialDescriptor(id=bytes.fromhex(c.credential_id))
        for c in existing
    ]
    selection_kwargs = {"user_verification": _user_verification()}
    attachment = _attachment()
    if attachment:
        selection_kwargs["authenticator_attachment"] = attachment

    options = generate_registration_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        rp_name=settings.WEBAUTHN_RP_NAME,
        user_name=username,
        user_id=_user_handle(),
        exclude_credentials=exclude,
        authenticator_selection=AuthenticatorSelectionCriteria(**selection_kwargs),
    )
    _pending_challenges["register"] = options.challenge
    # options_to_json returns a string; return it as a dict so that the
    # JSONResponse in the router does not double-encode it.
    return json.loads(options_to_json(options))


def build_authentication_options(db: Session):
    existing = db.query(WebAuthnCredential).all()
    allow = [
        PublicKeyCredentialDescriptor(id=bytes.fromhex(c.credential_id))
        for c in existing
    ]
    options = generate_authentication_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        allow_credentials=allow,
        user_verification=_user_verification(),
    )
    _pending_challenges["auth"] = options.challenge
    # see build_registration_options: return a dict instead of a string
    return json.loads(options_to_json(options))


def verify_passkey_authentication(db: Session, credential_json: dict) -> tuple[bool, str]:
    if not settings.auth_passkey_enabled:
        return False, "Passkey login is disabled"

    challenge = _pending_challenges.get("auth")
    if not challenge:
        return False, "No active login attempt found. Please try again."

    try:
        cred = parse_authentication_credential_json(json.dumps(credential_json))
        cred_id_hex = cred.raw_id.hex()

        stored = db.query(WebAuthnCredential).filter_by(credential_id=cred_id_hex).first()
        if not stored:
            return False, "Unknown passkey"

        result = verify_authentication_response(
            credential=cred,
            expected_challenge=challenge,
            expected_origin=settings.WEBAUTHN_ORIGIN,
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            credential_public_key=bytes.fromhex(stored.public_key),
            credential_current_sign_count=stored.sign_count,
            require_user_verification=_require_user_verification(),
        )

        stored.sign_count = result.new_sign_count
        stored.last_used_at = datetime.utcnow()
        db.commit()
        _pending_challenges.pop("auth", None)
        return True, "OK"
    except Exception as e:
        _pending_challenges.pop("auth", None)
        return False, f"Passkey verification failed: {str(e)}"


def store_new_credential(db: Session, credential_json: dict, nickname: str = None) -> tuple[bool, str]:
    challenge = _pending_challenges.get("register")
    if not challenge:
        return False, "No active registration found"

    try:
        cred = parse_registration_credential_json(json.dumps(credential_json))

        result = verify_registration_response(
            credential=cred,
            expected_challenge=challenge,
            expected_origin=settings.WEBAUTHN_ORIGIN,
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            require_user_verification=_require_user_verification(),
        )

        entry = WebAuthnCredential(
            credential_id=result.credential_id.hex(),
            public_key=result.credential_public_key.hex(),
            sign_count=result.sign_count,
            transports=",".join(credential_json.get("response", {}).get("transports", [])),
            nickname=nickname or "Passkey",
        )
        db.add(entry)
        db.commit()
        _pending_challenges.pop("register", None)
        return True, "OK"
    except Exception as e:
        _pending_challenges.pop("register", None)
        return False, f"Registration failed: {str(e)}"


def list_credentials(db: Session) -> list[dict]:
    creds = db.query(WebAuthnCredential).order_by(WebAuthnCredential.created_at.desc()).all()
    return [
        {
            "id": c.id,
            "nickname": c.nickname or "Passkey",
            "credential_id": c.credential_id[:16] + "…",
            "transports": c.transports,
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "last_used_at": c.last_used_at.isoformat() if c.last_used_at else None,
        }
        for c in creds
    ]


def delete_credential(db: Session, credential_row_id: int) -> tuple[bool, str]:
    cred = db.query(WebAuthnCredential).filter_by(id=credential_row_id).first()
    if not cred:
        return False, "Passkey not found"
    db.delete(cred)
    db.commit()
    return True, "OK"
