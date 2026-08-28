# FlareHub – Security Audit

Date: 2026-08-26 · Scope: complete codebase (backend, templates, Docker setup, dependencies)

FlareHub is a self-hosted dashboard for critical infrastructure (Cloudflare zone control).
This document summarizes the security model, the checks performed and the remaining
residual risks.

---

## 1. Authentication model (stateless, no cookie)

- **No session cookie.** After PIN/passkey login, the server issues a short-lived,
  signed token (itsdangerous, HMAC with `SESSION_SECRET_KEY`). The frontend stores it
  exclusively in the `sessionStorage` and sends it with every request as an
  `Authorization: Bearer <token>` header.
- **Consequence:** When the browser is closed, the token is gone. Every new visit
  requires a fresh PIN/passkey login. There is no server-side session store that
  could be compromised or stolen.
- Token lifetime: `SESSION_EXPIRY_HOURS` (default 4 h) as an upper limit.
- **Admin grant:** an additional hurdle for passkey management and all admin APIs
  (log viewer, DB maintenance, privacy toggle). Also no cookie – lives only in the
  `sessionStorage` and is sent as an `X-Admin-Grant` header. Signed, valid for a
  maximum of 10 minutes, immediately lockable via the "Lock admin" button. The
  admin token comparison uses `hmac.compare_digest` (timing-safe), with IP-based
  lockout like the PIN.
- **Privacy / IP masking:** security feed IPs are masked by default
  (`MASK_IPS_IN_FEED=true`, e.g. `185.220.xxx.xxx` / `2a01:4f8:xxx::`). Masking can only
  be temporarily disabled with a valid admin grant (checked server-side via
  `X-Reveal-IPs` + grant) – the frontend alone cannot unlock the raw IPs.
- **Log viewer:** collector logs are read-only and scrubbed server-side –
  secrets/tokens/URLs appear exclusively as `***` before they leave the API.
- **Passive analytics:** country and status code aggregation run exclusively through
  the read-only GraphQL endpoint `httpRequestsAdaptiveGroups`. FlareHub triggers no
  write DNS/WAF actions (the quick actions are also explicitly feature-gated and
  configurable).
- **PIN:** stored only as a bcrypt hash (`AUTH_PIN_HASH`; `AUTH_PIN` plaintext is
  hashed at startup), comparison via `bcrypt.checkpw`.
  Lockout after `AUTH_PIN_MAX_ATTEMPTS` failed attempts for `AUTH_PIN_LOCKOUT_SECONDS`
  (IP-based, in-memory). Default PIN length: 6 digits (6+ recommended for critical
  infrastructure, shorter possible via `AUTH_PIN_LENGTH`).
- **WebAuthn/Passkey:** RP-ID and origin validation, one-time challenges (removed
  after use), sign counter checks, optional user verification
  (`WEBAUTHN_USER_VERIFICATION=required` enforces it).

## 2. Checks & findings (all fixed)

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | Passkey options double-encoded (`options_to_json` returns a string) → passkey login/registration broken | Critical | Fixed |
| 2 | Empty Bearer header with missing Cloudflare token → `LocalProtocolError`/500 | Medium | Fixed (header only set with token + `httpx.HTTPError` catch) |
| 3 | Webhook URL (incl. secret) could end up in error logs | High | Fixed (only the error type is logged) |
| 4 | XSS via Cloudflare/user input (security feed, passkey names, zone values) | High | Fixed (frontend escaping + Jinja2 autoescape) |
| 5 | CSRF: state-changing requests without origin check | Medium | Fixed (origin middleware; low risk anyway thanks to Bearer token) |
| 6 | No cache protection for authenticated content | Medium | Fixed (`Cache-Control: no-store`, `HTTP_CACHE_NO_STORE`) |
| 7 | Missing security headers (clickjacking, MIME sniffing, CSP) | Medium | Fixed (CSP, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`) |
| 8 | Docker container ran as root | High | Fixed (non-root UID 1001) |
| 9 | Dependencies with known CVEs (fastapi/starlette/jinja2/python-dotenv/python-multipart) | High | Fixed (upgrade, `pip-audit`: 0 findings) |
| 10 | Session cookie as auth persistence | Medium | Removed (stateless token, no cookie) |

## 3. Operational protections (tested)

- **Rate limiting** on login/admin endpoints (`RATE_LIMIT_*`) – in-memory,
  therefore assumes **exactly one Uvicorn worker** (default, see Dockerfile).
- **CSRF/origin check** for POST/PUT/PATCH/DELETE (additional defense layer).
- **Feature gates & config guards:** quick actions / action center are disabled without
  configured Cloudflare credentials; every action is additionally checked server-side.
- **Database access exclusively via SQLAlchemy ORM** (no string SQL → no SQL injection).
- **No secrets in the repo:** `.env` is gitignored; default `SECRET` values are warned
  about on startup (`SESSION_SECRET_KEY` warning in the log).
- **Security headers:** CSP (`default-src 'self'`, no external origins), `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` (`SECURITY_HEADERS_ENABLED`).
- **Pinned dependencies** and checked via `pip-audit` (at audit time: 0 known vulnerabilities).

## 4. Residual risks & recommendations

1. **Token in `sessionStorage`:** a successful XSS attack can read the token.
   Countermeasures are implemented (escaping, CSP without external origins, no-store).
   Additionally recommended: serve the dashboard only over HTTPS (reverse proxy with SSL
   is strongly recommended; also enable HSTS on the proxy).
2. **PIN authentication:** the user chooses the PIN themselves – 4-digit PINs are
   brute-force-prone. For critical infrastructure prefer 6+ digits and `AUTH_MODE=passkey`
   (hardware token only).
3. **In-memory state (rate limiter, lockout, WebAuthn challenges):** applies per process.
   With more than one worker, rate limiting could be bypassed – **run only 1 worker**
   (default in the Dockerfile). A Redis/DB-based variant would be the next step.
4. **Docker volume:** the container runs as UID 1001; the host directory `./data`
   must get `chown -R 1001:1001 data/` once (see docker-compose.yml).
5. **Host header:** Uvicorn does not validate the Host header (no trusted-host filter).
   The WebAuthn origin check prevents passkey attacks; for internet access it is still
   recommended to put a reverse proxy with its own host whitelisting in front.
6. **Rate limiting per IP:** when accessed via a reverse proxy without
   `X-Forwarded-For` forwarding, all requests look like one IP (limited lockout effect).
   Configure the proxy accordingly (`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`).
7. **`AUTH_MODE=none`** exists deliberately only for isolated internal networks – do not expose to the internet.

## 5. Deployment checklist (critical infrastructure)

- [ ] `SESSION_SECRET_KEY` set to a random value (`python3 -c "import secrets; print(secrets.token_hex(32))"`)
- [ ] `AUTH_MODE=pin|passkey|both` (never `none` outside isolated networks)
- [ ] `AUTH_PIN_LENGTH=6`+ or `WEBAUTHN_USER_VERIFICATION=required` for passkeys
- [ ] `ADMIN_TOKEN` set (passkey management)
- [ ] `WEBAUTHN_RP_ID`/`WEBAUTHN_ORIGIN` set exactly to the calling domain/URL
- [ ] TLS via reverse proxy, HSTS on the proxy
- [ ] `chown -R 1001:1001 data/` (non-root container)
- [ ] No more than 1 Uvicorn worker
- [ ] Run `docker compose up -d --build` and play through the login flow (PIN + passkey) once
