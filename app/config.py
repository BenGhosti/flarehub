"""
FlareHub – central configuration.
Reads all values from the .env file (via os.environ) and provides sensible defaults.
"""
import os
from pathlib import Path

import bcrypt
from dotenv import load_dotenv

load_dotenv()


def _bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    val = os.getenv(name)
    if val is None or val.strip() == "":
        return default
    try:
        return int(val)
    except ValueError:
        return default


def _strip(name: str, default: str = "") -> str:
    """Reads a value and strips surrounding whitespace – copied values (tokens,
    zone IDs) often carry accidental spaces/newlines that break the API call."""
    val = os.getenv(name)
    return default if val is None else val.strip()


class Settings:
    # --- General ---
    APP_NAME: str = os.getenv("APP_NAME", "FlareHub")
    APP_ENV: str = os.getenv("APP_ENV", "production")
    TZ: str = os.getenv("TZ", "Europe/Berlin")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    APP_PORT: int = _int("APP_PORT", 8000)
    DEFAULT_THEME: str = os.getenv("DEFAULT_THEME", "dark")

    # --- Auth ---
    AUTH_MODE: str = os.getenv("AUTH_MODE", "both").lower()  # pin | passkey | both | none

    # Plaintext PIN (recommended for Docker: bcrypt hashes contain "$" characters that
    # Docker Compose may interpret as variable interpolation, mangling the hash).
    # If AUTH_PIN is set, it takes precedence over AUTH_PIN_HASH.
    AUTH_PIN: str = _strip("AUTH_PIN")
    # bcrypt hash of the PIN (alternative to AUTH_PIN). Generate with:
    #   python -c "import bcrypt; print(bcrypt.hashpw(b'123456', bcrypt.gensalt()).decode())"
    AUTH_PIN_HASH: str = os.getenv("AUTH_PIN_HASH", "")
    # PIN length. 6+ digits recommended for critical infrastructure.
    AUTH_PIN_LENGTH: int = _int("AUTH_PIN_LENGTH", 6)
    AUTH_PIN_MAX_ATTEMPTS: int = _int("AUTH_PIN_MAX_ATTEMPTS", 5)
    AUTH_PIN_LOCKOUT_SECONDS: int = _int("AUTH_PIN_LOCKOUT_SECONDS", 300)

    ADMIN_TOKEN: str = _strip("ADMIN_TOKEN")

    WEBAUTHN_RP_ID: str = os.getenv("WEBAUTHN_RP_ID", "localhost")
    WEBAUTHN_RP_NAME: str = os.getenv("WEBAUTHN_RP_NAME", "FlareHub")
    WEBAUTHN_ORIGIN: str = os.getenv("WEBAUTHN_ORIGIN", "http://localhost:8000")
    WEBAUTHN_USER_VERIFICATION: str = os.getenv("WEBAUTHN_USER_VERIFICATION", "preferred")
    WEBAUTHN_AUTHENTICATOR_ATTACHMENT: str = os.getenv("WEBAUTHN_AUTHENTICATOR_ATTACHMENT", "")

    SESSION_SECRET_KEY: str = os.getenv("SESSION_SECRET_KEY", "change-me-to-a-long-random-string")
    # Login token (Bearer) lifetime in hours. Since the token only lives in the
    # browser's sessionStorage, every new browser visit requires a fresh login anyway -
    # this is just an upper limit. Choose a low value for critical infrastructure (e.g. 2-4).
    SESSION_EXPIRY_HOURS: int = _int("SESSION_EXPIRY_HOURS", 4)
    # true (default): pages/API responses (except /static) get Cache-Control: no-store,
    # so no authenticated content is cached by the browser.
    HTTP_CACHE_NO_STORE: bool = _bool("HTTP_CACHE_NO_STORE", True)
    # true (default): sets security headers (CSP, X-Frame-Options: DENY,
    # X-Content-Type-Options: nosniff, Referrer-Policy) on all responses.
    SECURITY_HEADERS_ENABLED: bool = _bool("SECURITY_HEADERS_ENABLED", True)

    # --- Cloudflare ---
    CLOUDFLARE_API_TOKEN: str = _strip("CLOUDFLARE_API_TOKEN")
    CLOUDFLARE_ZONE_ID: str = _strip("CLOUDFLARE_ZONE_ID")
    CLOUDFLARE_ACCOUNT_ID: str = _strip("CLOUDFLARE_ACCOUNT_ID")
    CLOUDFLARE_API_BASE_URL: str = os.getenv("CLOUDFLARE_API_BASE_URL", "https://api.cloudflare.com/client/v4")
    CLOUDFLARE_GRAPHQL_URL: str = os.getenv("CLOUDFLARE_GRAPHQL_URL", "https://api.cloudflare.com/client/v4/graphql")
    CLOUDFLARE_API_TIMEOUT: int = _int("CLOUDFLARE_API_TIMEOUT", 15)

    # --- Collector ---
    COLLECTOR_INTERVAL_MINUTES: int = _int("COLLECTOR_INTERVAL_MINUTES", 10)
    COLLECTOR_RUN_ON_STARTUP: bool = _bool("COLLECTOR_RUN_ON_STARTUP", True)
    # Raw data (10-minute resolution) is compacted into hourly rollups after this time
    RAW_RETENTION_HOURS: int = _int("RAW_RETENTION_HOURS", 48)
    # Hourly rollups are compacted into daily rollups after this time
    HOURLY_RETENTION_DAYS: int = _int("HOURLY_RETENTION_DAYS", 30)
    # Daily rollups (long-term history) are deleted after this time
    DATA_RETENTION_DAYS: int = _int("DATA_RETENTION_DAYS", 730)
    # Individual threat events (security feed) are deleted after this time (raw, not aggregated)
    THREAT_EVENT_RETENTION_DAYS: int = _int("THREAT_EVENT_RETENTION_DAYS", 30)
    DATABASE_PATH: str = os.getenv("DATABASE_PATH", "/app/data/cloudflare.db")
    CHART_DEFAULT_DATAPOINTS: int = _int("CHART_DEFAULT_DATAPOINTS", 288)
    # Max. records a single Cloudflare GraphQL response may contain
    # (Cloudflare hard limit: 10,000 per response)
    COLLECTOR_MAX_RECORDS_PER_QUERY: int = _int("COLLECTOR_MAX_RECORDS_PER_QUERY", 500)

    # --- Feature Toggles ---
    FEATURE_REQUESTS_CHART: bool = _bool("FEATURE_REQUESTS_CHART", True)
    FEATURE_BANDWIDTH_CHART: bool = _bool("FEATURE_BANDWIDTH_CHART", True)
    FEATURE_CACHE_RATIO_CHART: bool = _bool("FEATURE_CACHE_RATIO_CHART", True)
    FEATURE_THREATS_CHART: bool = _bool("FEATURE_THREATS_CHART", True)
    FEATURE_SECURITY_FEED: bool = _bool("FEATURE_SECURITY_FEED", True)
    SECURITY_FEED_LIMIT: int = _int("SECURITY_FEED_LIMIT", 50)
    # Additional charts (all data is collected anyway, display only toggles)
    FEATURE_CACHE_DONUT_CHART: bool = _bool("FEATURE_CACHE_DONUT_CHART", True)      # Pie: Cached vs. Uncached
    FEATURE_THREAT_DONUT_CHART: bool = _bool("FEATURE_THREAT_DONUT_CHART", True)    # Pie: threat actions
    FEATURE_VISITORS_CHART: bool = _bool("FEATURE_VISITORS_CHART", True)            # Unique visitors
    FEATURE_PAGEVIEWS_CHART: bool = _bool("FEATURE_PAGEVIEWS_CHART", True)          # Page views
    FEATURE_CACHED_UNCACHED_CHART: bool = _bool("FEATURE_CACHED_UNCACHED_CHART", True)  # Stacked cached/uncached
    # Passive analytics (read-only GraphQL httpRequestsAdaptiveGroups)
    FEATURE_COUNTRY_CHART: bool = _bool("FEATURE_COUNTRY_CHART", True)              # Donut: top origin countries
    FEATURE_STATUS_CHART: bool = _bool("FEATURE_STATUS_CHART", True)                # Chart: status code groups (2xx-5xx)
    # Retention of passive analytics snapshots (countries/status codes) in days
    PASSIVE_RETENTION_DAYS: int = _int("PASSIVE_RETENTION_DAYS", 30)
    FEATURE_ACTION_CENTER: bool = _bool("FEATURE_ACTION_CENTER", True)
    FEATURE_QUICK_ACTIONS: bool = _bool("FEATURE_QUICK_ACTIONS", True)
    FEATURE_DEV_MODE_TOGGLE: bool = _bool("FEATURE_DEV_MODE_TOGGLE", True)
    FEATURE_PURGE_CACHE: bool = _bool("FEATURE_PURGE_CACHE", True)
    FEATURE_UNDER_ATTACK_TOGGLE: bool = _bool("FEATURE_UNDER_ATTACK_TOGGLE", True)
    DASHBOARD_AUTO_REFRESH_SECONDS: int = _int("DASHBOARD_AUTO_REFRESH_SECONDS", 60)

    # --- Privacy / Masking ---
    # true (default): IPs in the security feed are masked (185.220.xxx.xxx).
    # Masking can be temporarily disabled on the admin page (browser session only),
    # which requires an active admin grant.
    MASK_IPS_IN_FEED: bool = _bool("MASK_IPS_IN_FEED", True)

    # --- Webhook alerting (passive, optional) ---
    # WEBHOOK_ENABLED=true enables notifications on threat spikes and 5xx errors.
    # WEBHOOK_TYPE: discord | telegram | gotify
    WEBHOOK_ENABLED: bool = _bool("WEBHOOK_ENABLED", False)
    # Backwards compatibility: if WEBHOOK_URL is empty, NOTIFY_WEBHOOK_URL is used
    WEBHOOK_URL: str = os.getenv("WEBHOOK_URL", os.getenv("NOTIFY_WEBHOOK_URL", ""))
    WEBHOOK_TYPE: str = os.getenv("WEBHOOK_TYPE", "discord").lower()
    WEBHOOK_ON_THREAT_SPIKE: bool = _bool("WEBHOOK_ON_THREAT_SPIKE", True)
    WEBHOOK_ON_5XX: bool = _bool("WEBHOOK_ON_5XX", True)
    # Thresholds (falls back to the old NOTIFY_* variables)
    WEBHOOK_THREAT_THRESHOLD: int = _int("WEBHOOK_THREAT_THRESHOLD", _int("NOTIFY_THREAT_THRESHOLD", 100))
    WEBHOOK_5XX_THRESHOLD: int = _int("WEBHOOK_5XX_THRESHOLD", 50)
    # Send webhook notification after a cache purge quick action
    NOTIFY_ON_CACHE_PURGE: bool = _bool("NOTIFY_ON_CACHE_PURGE", True)
    # Send webhook notification when the Under Attack Mode is toggled
    NOTIFY_ON_UNDER_ATTACK_TOGGLE: bool = _bool("NOTIFY_ON_UNDER_ATTACK_TOGGLE", True)
    # Telegram: chat ID, unless it is part of the URL (alternative: ?chat_id=... in WEBHOOK_URL)
    WEBHOOK_TELEGRAM_CHAT_ID: str = os.getenv("WEBHOOK_TELEGRAM_CHAT_ID", "")
    # Gotify: app token (X-Gotify-Key) - alternatively it can be part of the URL
    WEBHOOK_GOTIFY_TOKEN: str = os.getenv("WEBHOOK_GOTIFY_TOKEN", "")

    # --- Rate limiting ---
    RATE_LIMIT_ENABLED: bool = _bool("RATE_LIMIT_ENABLED", True)
    RATE_LIMIT_LOGIN_ATTEMPTS_PER_MINUTE: int = _int("RATE_LIMIT_LOGIN_ATTEMPTS_PER_MINUTE", 10)

    # --- Security / Proxy ---
    # true: honor X-Forwarded-For for rate limiting / PIN lockout. ONLY enable when
    # FlareHub runs behind a trusted reverse proxy that overwrites this header.
    # false (default): uses the direct peer IP - behind a proxy all clients share
    # one lockout bucket (attacker could lock everyone out), but the header cannot
    # be spoofed.
    TRUST_PROXY_HEADERS: bool = _bool("TRUST_PROXY_HEADERS", False)
    # Min. seconds between manual collector runs (/api/collector/run-now) to protect
    # the Cloudflare GraphQL quota from accidental or malicious flooding.
    MANUAL_RUN_COOLDOWN_SECONDS: int = _int("MANUAL_RUN_COOLDOWN_SECONDS", 30)

    @property
    def webhook_active(self) -> bool:
        return self.WEBHOOK_ENABLED and bool(self.WEBHOOK_URL)

    @property
    def auth_pin_enabled(self) -> bool:
        return self.AUTH_MODE in ("pin", "both")

    @property
    def auth_passkey_enabled(self) -> bool:
        return self.AUTH_MODE in ("passkey", "both")

    @property
    def auth_disabled(self) -> bool:
        return self.AUTH_MODE == "none"


settings = Settings()

# If a plaintext PIN is configured, derive the bcrypt hash from it once at startup.
# AUTH_PIN takes precedence over AUTH_PIN_HASH.
if settings.AUTH_PIN:
    settings.AUTH_PIN_HASH = bcrypt.hashpw(settings.AUTH_PIN.encode(), bcrypt.gensalt()).decode()

# Make sure the data directory exists
Path(settings.DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
