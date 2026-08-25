"""
FlareHub – zentrale Konfiguration.
Liest alle Werte aus der .env (via os.environ) und stellt sinnvolle Defaults bereit.
"""
import os
from pathlib import Path
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


class Settings:
    # --- Allgemein ---
    APP_NAME: str = os.getenv("APP_NAME", "FlareHub")
    APP_ENV: str = os.getenv("APP_ENV", "production")
    TZ: str = os.getenv("TZ", "Europe/Berlin")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    APP_PORT: int = _int("APP_PORT", 8000)
    DEFAULT_THEME: str = os.getenv("DEFAULT_THEME", "dark")

    # --- Auth ---
    AUTH_MODE: str = os.getenv("AUTH_MODE", "both").lower()  # pin | passkey | both | none

    AUTH_PIN_HASH: str = os.getenv("AUTH_PIN_HASH", "")
    AUTH_PIN_LENGTH: int = _int("AUTH_PIN_LENGTH", 4)
    AUTH_PIN_MAX_ATTEMPTS: int = _int("AUTH_PIN_MAX_ATTEMPTS", 5)
    AUTH_PIN_LOCKOUT_SECONDS: int = _int("AUTH_PIN_LOCKOUT_SECONDS", 300)

    ADMIN_TOKEN: str = os.getenv("ADMIN_TOKEN", "")

    WEBAUTHN_RP_ID: str = os.getenv("WEBAUTHN_RP_ID", "localhost")
    WEBAUTHN_RP_NAME: str = os.getenv("WEBAUTHN_RP_NAME", "FlareHub")
    WEBAUTHN_ORIGIN: str = os.getenv("WEBAUTHN_ORIGIN", "http://localhost:8000")
    WEBAUTHN_USER_VERIFICATION: str = os.getenv("WEBAUTHN_USER_VERIFICATION", "preferred")
    WEBAUTHN_AUTHENTICATOR_ATTACHMENT: str = os.getenv("WEBAUTHN_AUTHENTICATOR_ATTACHMENT", "")

    SESSION_SECRET_KEY: str = os.getenv("SESSION_SECRET_KEY", "change-me-to-a-long-random-string")
    SESSION_COOKIE_NAME: str = os.getenv("SESSION_COOKIE_NAME", "flarehub_session")
    SESSION_EXPIRY_HOURS: int = _int("SESSION_EXPIRY_HOURS", 12)
    SESSION_COOKIE_SECURE: bool = _bool("SESSION_COOKIE_SECURE", False)
    SESSION_COOKIE_SAMESITE: str = os.getenv("SESSION_COOKIE_SAMESITE", "lax")
    SESSION_REMEMBER_ME_DAYS: int = _int("SESSION_REMEMBER_ME_DAYS", 30)

    # --- Cloudflare ---
    CLOUDFLARE_API_TOKEN: str = os.getenv("CLOUDFLARE_API_TOKEN", "")
    CLOUDFLARE_ZONE_ID: str = os.getenv("CLOUDFLARE_ZONE_ID", "")
    CLOUDFLARE_ACCOUNT_ID: str = os.getenv("CLOUDFLARE_ACCOUNT_ID", "")
    CLOUDFLARE_API_BASE_URL: str = os.getenv("CLOUDFLARE_API_BASE_URL", "https://api.cloudflare.com/client/v4")
    CLOUDFLARE_GRAPHQL_URL: str = os.getenv("CLOUDFLARE_GRAPHQL_URL", "https://api.cloudflare.com/client/v4/graphql")
    CLOUDFLARE_API_TIMEOUT: int = _int("CLOUDFLARE_API_TIMEOUT", 15)

    # --- Collector ---
    COLLECTOR_INTERVAL_MINUTES: int = _int("COLLECTOR_INTERVAL_MINUTES", 10)
    COLLECTOR_RUN_ON_STARTUP: bool = _bool("COLLECTOR_RUN_ON_STARTUP", True)
    DATA_RETENTION_DAYS: int = _int("DATA_RETENTION_DAYS", 90)
    DATABASE_PATH: str = os.getenv("DATABASE_PATH", "/app/data/cloudflare.db")
    CHART_DEFAULT_DATAPOINTS: int = _int("CHART_DEFAULT_DATAPOINTS", 144)

    # --- Feature Toggles ---
    FEATURE_REQUESTS_CHART: bool = _bool("FEATURE_REQUESTS_CHART", True)
    FEATURE_BANDWIDTH_CHART: bool = _bool("FEATURE_BANDWIDTH_CHART", True)
    FEATURE_CACHE_RATIO_CHART: bool = _bool("FEATURE_CACHE_RATIO_CHART", True)
    FEATURE_THREATS_CHART: bool = _bool("FEATURE_THREATS_CHART", True)
    FEATURE_SECURITY_FEED: bool = _bool("FEATURE_SECURITY_FEED", True)
    SECURITY_FEED_LIMIT: int = _int("SECURITY_FEED_LIMIT", 50)
    FEATURE_QUICK_ACTIONS: bool = _bool("FEATURE_QUICK_ACTIONS", True)
    FEATURE_DEV_MODE_TOGGLE: bool = _bool("FEATURE_DEV_MODE_TOGGLE", True)
    FEATURE_PURGE_CACHE: bool = _bool("FEATURE_PURGE_CACHE", True)
    FEATURE_UNDER_ATTACK_TOGGLE: bool = _bool("FEATURE_UNDER_ATTACK_TOGGLE", True)
    DASHBOARD_AUTO_REFRESH_SECONDS: int = _int("DASHBOARD_AUTO_REFRESH_SECONDS", 60)

    # --- Notifications ---
    NOTIFY_WEBHOOK_URL: str = os.getenv("NOTIFY_WEBHOOK_URL", "")
    NOTIFY_ON_UNDER_ATTACK_TOGGLE: bool = _bool("NOTIFY_ON_UNDER_ATTACK_TOGGLE", True)
    NOTIFY_ON_CACHE_PURGE: bool = _bool("NOTIFY_ON_CACHE_PURGE", True)
    NOTIFY_THREAT_THRESHOLD: int = _int("NOTIFY_THREAT_THRESHOLD", 100)

    # --- Rate Limiting ---
    RATE_LIMIT_ENABLED: bool = _bool("RATE_LIMIT_ENABLED", True)
    RATE_LIMIT_LOGIN_ATTEMPTS_PER_MINUTE: int = _int("RATE_LIMIT_LOGIN_ATTEMPTS_PER_MINUTE", 10)

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

# Sicherstellen, dass das Datenverzeichnis existiert
Path(settings.DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
