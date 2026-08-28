# FlareHub

A lean Cloudflare Analytics & Quick Actions dashboard for Unraid/Docker.

- FastAPI backend + Jinja2 templates + plain JS/CSS (no SPA)
- **Stateless auth without cookies:** PIN/passkey login issues a short-lived token
  (only in the browser's `sessionStorage`) – every new visit requires a fresh login
- PIN and/or passkey/WebAuthn login (controlled via `.env`)
- Admin-token-protected passkey management (add/delete), separate from the normal login
- Analytics collector fetches GraphQL metrics from Cloudflare every X minutes (`httpRequests1mGroups`)
- Period selection (6h/24h/7d/30d/90d/1y) with automatic resolution
- Charts: requests, bandwidth, cache ratio, cached vs. uncached, unique visitors,
  page views, threats (Chart.js, served locally – no CDN)
- Pie charts: cache split (cached/uncached) and threat actions (block/challenge/...)
- **Passive analytics** (read-only): top origin countries (donut) and
  HTTP status code groups (2xx–5xx) – no write DNS/WAF actions
- **Privacy / IP masking:** security feed IPs are masked by default
  (`185.220.xxx.xxx`), temporarily disableable on the admin page
- Security feed (WAF/firewall events)
- Quick actions: dev mode, cache purge, under attack mode
- **Action Center** (`/actions`): cache purge for specific URLs, manual collector run,
  read-only zone status overview
- **Admin page** (`/admin`): passkey management, SQLite maintenance (VACUUM/ANALYZE),
  scrubbed log viewer, privacy toggle – protected by `ADMIN_TOKEN` (grant only in
  sessionStorage, "Lock admin" button)
- **Webhook alerting** (optional): Discord/Telegram/Gotify on threat spikes and
  5xx errors (passive)
- Multi-level data aggregation (raw → hourly → daily) to keep the DB permanently small
- Collector diagnostics (last run, errors, storage statistics) on the settings page
- Security hardening: security headers (CSP etc.), non-root Docker, PIN lockout, rate limiting,
  `pip-audit`-checked dependencies – see [SECURITY.md](SECURITY.md)

## Setup

1. Copy `.env.example` to `.env` and adjust:
   ```bash
   cp .env.example .env
   ```

2. Enter Cloudflare credentials (`CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ZONE_ID`).
   The API token needs the permissions:
   - Zone → Analytics → Read
   - Zone → Cache Purge → Edit
   - Zone → Zone Settings → Edit

3. Choose the auth mode (`AUTH_MODE=pin|passkey|both|none`).

   For PIN login, set `AUTH_PIN` to the plaintext PIN (recommended for Docker –
   bcrypt hashes contain `$` characters that Docker Compose interprets as variable
   interpolation). Alternatively generate a bcrypt hash:
   ```bash
   python3 -c "import bcrypt; print(bcrypt.hashpw(b'YOUR_PIN', bcrypt.gensalt()).decode())"
   ```
   and put it in `AUTH_PIN_HASH` (escape `$` as `$$` when using Docker).

   For passkey login, set `WEBAUTHN_RP_ID` and `WEBAUTHN_ORIGIN` to the actual domain/URL.

4. Set `SESSION_SECRET_KEY` to a long random string:
   ```bash
   python3 -c "import secrets; print(secrets.token_hex(32))"
   ```

5. Start:
   ```bash
   docker compose up -d --build
   ```

6. Set `ADMIN_TOKEN` (long, random value) to unlock passkey management:
   ```bash
   python3 -c "import secrets; print(secrets.token_hex(24))"
   ```

7. Open the dashboard at `http://<host>:<HOST_PORT>` (default external port: **1111**,
   configurable via `HOST_PORT` in the `.env`) and log in with the PIN. Under
   **Settings → Unlock passkey management**, enter the admin token (valid for 10 minutes)
   and add or delete passkeys there. The admin token is an additional hurdle
   separate from the normal login – even with an active session, passkey
   management is not possible without the correct token.

## Security

- **No session cookies:** after PIN/passkey login, a short-lived, signed token is
  issued that lives only in the browser's `sessionStorage` and is sent as an
  `Authorization: Bearer` header. When the browser is closed, it is gone –
  **every new visit requires a fresh PIN/passkey login**
  (`SESSION_EXPIRY_HOURS` = upper limit, default 4 h).
- **Admin token grant:** valid for 10 minutes, only in `sessionStorage` (`X-Admin-Grant` header),
  never on disk. Passkey management is therefore doubly protected.
- **PIN lockout:** after `AUTH_PIN_MAX_ATTEMPTS` failed attempts per IP, login is blocked
  for `AUTH_PIN_LOCKOUT_SECONDS` seconds; additionally, rate limiting on login endpoints.
- **CSRF:** all state-changing requests are checked for same-origin via the Origin header.
- **Security headers:** CSP (own resources only), `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` (`SECURITY_HEADERS_ENABLED`).
- **No browser caching:** pages & APIs get `Cache-Control: no-store` (`HTTP_CACHE_NO_STORE`).
- **XSS:** all Cloudflare/user input is escaped (frontend + Jinja2 autoescape).
- **Docker runs non-root** (UID 1001, run `chown -R 1001:1001 data/` once).
- **Pinned dependencies + `pip-audit` checked** (0 known vulnerabilities).
- Details: see [SECURITY.md](SECURITY.md) (full audit, residual risks, checklist).

## Configuration

All settings run via the `.env` — see `.env.example` for the complete,
commented list (auth, session, Cloudflare, collector, data retention, feature toggles,
notifications, rate limiting).

## Data storage

The analytics data passes through a three-stage aggregation so that the SQLite database
stays small even after years of operation, without losing the long-term trend:

| Stage | Resolution | Retention (default) | .env variable |
|---|---|---|---|
| Raw data | 10 min. (`COLLECTOR_INTERVAL_MINUTES`) | 48 h | `RAW_RETENTION_HOURS` |
| Hourly rollup | 1 h | 30 days | `HOURLY_RETENTION_DAYS` |
| Daily rollup | 1 day | 730 days (~2 years) | `DATA_RETENTION_DAYS` |

The compaction runs automatically after every collector run. The period selection in the
dashboard automatically picks the matching stage (e.g. "1 year" uses the daily rollups
instead of querying millions of raw data points). On the settings page, the
**System & Data Storage** section shows the current row count per stage as well as the
status of the last collector run (incl. error message, e.g. if the Cloudflare token is invalid).

## Test server (UI preview without Cloudflare)

On Windows (also directly from a NAS share), `test-webserver.bat` starts a
dummy server to review the complete UI (login, dashboard, charts, security feed,
settings) without real Cloudflare credentials:

```bat
test-webserver.bat          :: default port 8000
test-webserver.bat 8080     :: custom port
```

- Login: **PIN 1234**
- Admin token (Settings → Passkey management): **test-admin-token**
- Automatically creates a local Python environment (`%LOCALAPPDATA%\FlareHub\venv`)
  and installs the dependencies on first start.
- Populates `data/test.db` via `scripts/seed_demo_data.py` with realistic
  sample data (all periods 6h–1y, 50 security events).
- Opens the browser automatically; stop with `Ctrl+C` in the console window.

## Cloudflare API – notes

- Used GraphQL node: `httpRequests1mGroups` (zone-scoped, 10-minute raw values for
  requests, cache hits, bandwidth, threats, page views, unique visitors).
- **Automatic plan fallback:** the `httpRequests1mGroups` dataset is only available to
  zones on higher plans. If Cloudflare responds with "zone does not have access to the path",
  FlareHub automatically falls back to `httpRequests1hGroups` (hourly aggregates, available
  on all plans) – the collector then stores one snapshot per hour instead of per 10 minutes.
- Firewall events via `firewallEventsAdaptive`.
- Cloudflare limits the collector respects: GraphQL rate limit on Cloudflare's side (default
  300 queries/5 min.), max. 10,000 records per response (we query significantly more
  conservatively, see `COLLECTOR_MAX_RECORDS_PER_QUERY`), and 401/403/429 responses are
  detected and logged understandably in the collector log instead of throwing a generic error.
- Free-plan users have limited historical access to some datasets (e.g. firewall
  events only 14 days back) – that is a Cloudflare plan limitation, not a FlareHub restriction.

## Structure

```
flarehub/
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── .env.example
├── SECURITY.md         # Security audit (model, findings, residual risks, checklist)
├── test-webserver.bat  # Windows test server with demo data (PIN 1234)
└── app/
    ├── main.py         # FastAPI routes
    ├── auth.py         # Stateless token auth + PIN + WebAuthn + admin token gate
    ├── collector.py    # Cloudflare GraphQL collector & zone actions + passive analytics
    ├── config.py       # .env settings
    ├── database.py     # SQLAlchemy models + rollup/aggregation logic + DB maintenance
    ├── templates/
    │   ├── login.html
    │   ├── dashboard.html
    │   ├── actions.html
    │   ├── settings.html
    │   └── admin.html
    └── static/
        ├── styles.css
        ├── auth.js     # Stateless auth helpers (sessionStorage + Bearer header)
        ├── webauthn.js
        └── vendor/chart.umd.min.js  # Chart.js local (offline-capable)
```
