"""
FlareHub – Authentifizierung: PIN + WebAuthn/Passkey.
Verhalten wird komplett über AUTH_MODE in der .env gesteuert (pin | passkey | both | none).
"""
import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta

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

# In-memory Challenge-Store (kurzlebig, kein Persistenzbedarf)
_pending_challenges: dict = {}
# In-memory PIN-Lockout-Tracking je IP
_pin_failures: dict = {}


# ---------------------------------------------------------------------------
# Session / Cookie
# ---------------------------------------------------------------------------
def create_session_token(remember_me: bool = False) -> str:
    return serializer.dumps({"authenticated": True, "ts": time.time(), "remember": remember_me})


def verify_session_token(token: str) -> bool:
    max_age_seconds = (
        settings.SESSION_REMEMBER_ME_DAYS * 86400
        if _token_has_remember(token)
        else settings.SESSION_EXPIRY_HOURS * 3600
    )
    try:
        data = serializer.loads(token, max_age=max_age_seconds)
        return bool(data.get("authenticated"))
    except (BadSignature, SignatureExpired):
        return False


def _token_has_remember(token: str) -> bool:
    try:
        data = serializer.loads(token, max_age=settings.SESSION_REMEMBER_ME_DAYS * 86400)
        return bool(data.get("remember"))
    except Exception:
        return False


def get_current_session(request: Request) -> bool:
    """Dependency: prüft ob Request authentifiziert ist. Bei AUTH_MODE=none immer True."""
    if settings.auth_disabled:
        return True
    token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if not verify_session_token(token):
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    return True


def set_session_cookie(response, remember_me: bool = False):
    token = create_session_token(remember_me)
    max_age = (
        settings.SESSION_REMEMBER_ME_DAYS * 86400
        if remember_me
        else settings.SESSION_EXPIRY_HOURS * 3600
    )
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=token,
        max_age=max_age,
        httponly=True,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite=settings.SESSION_COOKIE_SAMESITE,
    )


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
        return False, "PIN-Login ist deaktiviert"

    locked, remaining = _is_locked_out(client_ip)
    if locked:
        return False, f"Zu viele Fehlversuche. Erneut versuchen in {remaining}s"

    if not settings.AUTH_PIN_HASH:
        return False, "Kein PIN konfiguriert (AUTH_PIN_HASH fehlt in .env)"

    try:
        valid = bcrypt.checkpw(pin.encode(), settings.AUTH_PIN_HASH.encode())
    except ValueError:
        valid = False

    if valid:
        _clear_pin_failures(client_ip)
        return True, "OK"
    else:
        _register_pin_failure(client_ip)
        return False, "Falsche PIN"


# ---------------------------------------------------------------------------
# Admin-Token (Passkey-Verwaltung)
# ---------------------------------------------------------------------------
# In-memory Lockout-Tracking für Admin-Token-Versuche, je IP (analog zum PIN-Lockout)
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
    """Prüft das Admin-Token aus der .env. Getrennt vom normalen Login gedacht:
    schützt zusätzlich die Passkey-Verwaltung, auch wenn bereits eine Session besteht."""
    if not settings.ADMIN_TOKEN:
        return False, "Kein Admin-Token konfiguriert (ADMIN_TOKEN fehlt in .env)"

    locked, remaining = _admin_locked_out(client_ip)
    if locked:
        return False, f"Zu viele Fehlversuche. Erneut versuchen in {remaining}s"

    if not token:
        return False, "Admin-Token erforderlich"

    valid = hmac.compare_digest(token, settings.ADMIN_TOKEN)

    if valid:
        _admin_token_failures.pop(client_ip, None)
        return True, "OK"
    else:
        count, first_ts = _admin_token_failures.get(client_ip, (0, time.time()))
        _admin_token_failures[client_ip] = (count + 1, first_ts)
        return False, "Ungültiges Admin-Token"


def create_admin_token_grant() -> str:
    """Kurzlebiges, signiertes Token, das nach erfolgreicher Admin-Token-Eingabe
    ausgestellt wird und die Passkey-Verwaltungsendpunkte für kurze Zeit freischaltet."""
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
    """Stabiler User-Handle für den einzelnen Admin-Account.

    Wird deterministisch aus SESSION_SECRET_KEY abgeleitet, damit alle registrierten
    Passkeys denselben UserHandle haben und keine zufällig wechselnde ID entsteht."""
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
    return options_to_json(options)


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
    return options_to_json(options)


def verify_passkey_authentication(db: Session, credential_json: dict) -> tuple[bool, str]:
    if not settings.auth_passkey_enabled:
        return False, "Passkey-Login ist deaktiviert"

    challenge = _pending_challenges.get("auth")
    if not challenge:
        return False, "Kein aktiver Login-Versuch gefunden. Bitte erneut starten."

    try:
        cred = parse_authentication_credential_json(json.dumps(credential_json))
        cred_id_hex = cred.raw_id.hex()

        stored = db.query(WebAuthnCredential).filter_by(credential_id=cred_id_hex).first()
        if not stored:
            return False, "Unbekannter Passkey"

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
        return False, f"Passkey-Verifizierung fehlgeschlagen: {str(e)}"


def store_new_credential(db: Session, credential_json: dict, nickname: str = None) -> tuple[bool, str]:
    challenge = _pending_challenges.get("register")
    if not challenge:
        return False, "Keine aktive Registrierung gefunden"

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
        return False, f"Registrierung fehlgeschlagen: {str(e)}"


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
        return False, "Passkey nicht gefunden"
    db.delete(cred)
    db.commit()
    return True, "OK"
