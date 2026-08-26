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
    # Laenge der PIN. 6+ Stellen fuer kritische Infrastruktur empfohlen.
    AUTH_PIN_LENGTH: int = _int("AUTH_PIN_LENGTH", 6)
    AUTH_PIN_MAX_ATTEMPTS: int = _int("AUTH_PIN_MAX_ATTEMPTS", 5)
    AUTH_PIN_LOCKOUT_SECONDS: int = _int("AUTH_PIN_LOCKOUT_SECONDS", 300)

    ADMIN_TOKEN: str = os.getenv("ADMIN_TOKEN", "")

    WEBAUTHN_RP_ID: str = os.getenv("WEBAUTHN_RP_ID", "localhost")
    WEBAUTHN_RP_NAME: str = os.getenv("WEBAUTHN_RP_NAME", "FlareHub")
    WEBAUTHN_ORIGIN: str = os.getenv("WEBAUTHN_ORIGIN", "http://localhost:8000")
    WEBAUTHN_USER_VERIFICATION: str = os.getenv("WEBAUTHN_USER_VERIFICATION", "preferred")
    WEBAUTHN_AUTHENTICATOR_ATTACHMENT: str = os.getenv("WEBAUTHN_AUTHENTICATOR_ATTACHMENT", "")

    SESSION_SECRET_KEY: str = os.getenv("SESSION_SECRET_KEY", "change-me-to-a-long-random-string")
    # Gültigkeit des Login-Tokens (Bearer) in Stunden. Da das Token nur im
    # sessionStorage des Browsers liegt, muss man sich bei jedem neuen
    # Browser-Besuch ohnehin neu anmelden - dies ist nur ein oberes Limit.
    # Für kritische Infrastruktur eher niedrig waehlen (z.B. 2-4).
    SESSION_EXPIRY_HOURS: int = _int("SESSION_EXPIRY_HOURS", 4)
    # true (Standard): Seiten/API-Antworten (ausser /static) erhalten
    # Cache-Control: no-store, damit kein authentifizierter Inhalt im Browser gecacht wird.
    HTTP_CACHE_NO_STORE: bool = _bool("HTTP_CACHE_NO_STORE", True)
    # true (Standard): setzt Security-Header (CSP, X-Frame-Options: DENY,
    # X-Content-Type-Options: nosniff, Referrer-Policy) auf alle Antworten.
    SECURITY_HEADERS_ENABLED: bool = _bool("SECURITY_HEADERS_ENABLED", True)

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
    # Rohdaten (10-Minuten-Auflösung) werden nach dieser Zeit zu Stunden-Rollups verdichtet
    RAW_RETENTION_HOURS: int = _int("RAW_RETENTION_HOURS", 48)
    # Stunden-Rollups werden nach dieser Zeit zu Tages-Rollups verdichtet
    HOURLY_RETENTION_DAYS: int = _int("HOURLY_RETENTION_DAYS", 30)
    # Tages-Rollups (Langzeitverlauf) werden nach dieser Zeit gelöscht
    DATA_RETENTION_DAYS: int = _int("DATA_RETENTION_DAYS", 730)
    # Einzelne Threat-Events (Security-Feed) werden nach dieser Zeit gelöscht (Rohdaten, nicht aggregiert)
    THREAT_EVENT_RETENTION_DAYS: int = _int("THREAT_EVENT_RETENTION_DAYS", 30)
    DATABASE_PATH: str = os.getenv("DATABASE_PATH", "/app/data/cloudflare.db")
    CHART_DEFAULT_DATAPOINTS: int = _int("CHART_DEFAULT_DATAPOINTS", 288)
    # Max. Anzahl Records, die eine einzelne Cloudflare-GraphQL-Antwort umfassen darf
    # (Cloudflare-Hardlimit: 10.000 pro Response)
    COLLECTOR_MAX_RECORDS_PER_QUERY: int = _int("COLLECTOR_MAX_RECORDS_PER_QUERY", 500)

    # --- Feature Toggles ---
    FEATURE_REQUESTS_CHART: bool = _bool("FEATURE_REQUESTS_CHART", True)
    FEATURE_BANDWIDTH_CHART: bool = _bool("FEATURE_BANDWIDTH_CHART", True)
    FEATURE_CACHE_RATIO_CHART: bool = _bool("FEATURE_CACHE_RATIO_CHART", True)
    FEATURE_THREATS_CHART: bool = _bool("FEATURE_THREATS_CHART", True)
    FEATURE_SECURITY_FEED: bool = _bool("FEATURE_SECURITY_FEED", True)
    SECURITY_FEED_LIMIT: int = _int("SECURITY_FEED_LIMIT", 50)
    # Zusätzliche Charts (alle Daten werden ohnehin gesammelt)
    FEATURE_CACHE_DONUT_CHART: bool = _bool("FEATURE_CACHE_DONUT_CHART", True)      # Pie: Cached vs. Uncached
    FEATURE_THREAT_DONUT_CHART: bool = _bool("FEATURE_THREAT_DONUT_CHART", True)    # Pie: Threat-Aktionen
    FEATURE_VISITORS_CHART: bool = _bool("FEATURE_VISITORS_CHART", True)            # Unique Visitors
    FEATURE_PAGEVIEWS_CHART: bool = _bool("FEATURE_PAGEVIEWS_CHART", True)          # Page Views
    FEATURE_CACHED_UNCACHED_CHART: bool = _bool("FEATURE_CACHED_UNCACHED_CHART", True)  # Stacked Cached/Uncached
    # Passive Analytics (read-only GraphQL httpRequestsAdaptiveGroups)
    FEATURE_COUNTRY_CHART: bool = _bool("FEATURE_COUNTRY_CHART", True)              # Donut: Top-Herkunftsländer
    FEATURE_STATUS_CHART: bool = _bool("FEATURE_STATUS_CHART", True)                # Chart: Statuscode-Gruppen (2xx-5xx)
    # Aufbewahrung der passiven Analytics-Snapshots (Country/StatusCode) in Tagen
    PASSIVE_RETENTION_DAYS: int = _int("PASSIVE_RETENTION_DAYS", 30)
    FEATURE_ACTION_CENTER: bool = _bool("FEATURE_ACTION_CENTER", True)
    FEATURE_QUICK_ACTIONS: bool = _bool("FEATURE_QUICK_ACTIONS", True)
    FEATURE_DEV_MODE_TOGGLE: bool = _bool("FEATURE_DEV_MODE_TOGGLE", True)
    FEATURE_PURGE_CACHE: bool = _bool("FEATURE_PURGE_CACHE", True)
    FEATURE_UNDER_ATTACK_TOGGLE: bool = _bool("FEATURE_UNDER_ATTACK_TOGGLE", True)
    DASHBOARD_AUTO_REFRESH_SECONDS: int = _int("DASHBOARD_AUTO_REFRESH_SECONDS", 60)

    # --- Privacy / Masking ---
    # true (Standard): IPs im Security-Feed werden maskiert (185.220.xxx.xxx).
    # Auf der Admin-Seite kann die Maskierung temporär (nur Browser-Session)
    # deaktiviert werden - das erfordert einen aktiven Admin-Grant.
    MASK_IPS_IN_FEED: bool = _bool("MASK_IPS_IN_FEED", True)

    # --- Webhook-Alerting (passiv, optional) ---
    # WEBHOOK_ENABLED=true aktiviert Benachrichtigungen bei Threat-Spikes und 5xx-Fehlern.
    # WEBHOOK_TYPE: discord | telegram | gotify
    WEBHOOK_ENABLED: bool = _bool("WEBHOOK_ENABLED", False)
    # Rückwärtskompatibilität: falls WEBHOOK_URL leer, wird NOTIFY_WEBHOOK_URL übernommen
    WEBHOOK_URL: str = os.getenv("WEBHOOK_URL", os.getenv("NOTIFY_WEBHOOK_URL", ""))
    WEBHOOK_TYPE: str = os.getenv("WEBHOOK_TYPE", "discord").lower()
    WEBHOOK_ON_THREAT_SPIKE: bool = _bool("WEBHOOK_ON_THREAT_SPIKE", True)
    WEBHOOK_ON_5XX: bool = _bool("WEBHOOK_ON_5XX", True)
    # Schwellenwerte (Fallback auf die alten NOTIFY_*-Variablen)
    WEBHOOK_THREAT_THRESHOLD: int = _int("WEBHOOK_THREAT_THRESHOLD", _int("NOTIFY_THREAT_THRESHOLD", 100))
    WEBHOOK_5XX_THRESHOLD: int = _int("WEBHOOK_5XX_THRESHOLD", 50)
    # Telegram: Chat-ID, falls sie nicht in der URL steht (Alternative: ?chat_id=... in WEBHOOK_URL)
    WEBHOOK_TELEGRAM_CHAT_ID: str = os.getenv("WEBHOOK_TELEGRAM_CHAT_ID", "")
    # Gotify: App-Token (X-Gotify-Key) - alternativ kann es in der URL stehen
    WEBHOOK_GOTIFY_TOKEN: str = os.getenv("WEBHOOK_GOTIFY_TOKEN", "")

    # --- Rate Limiting ---
    RATE_LIMIT_ENABLED: bool = _bool("RATE_LIMIT_ENABLED", True)
    RATE_LIMIT_LOGIN_ATTEMPTS_PER_MINUTE: int = _int("RATE_LIMIT_LOGIN_ATTEMPTS_PER_MINUTE", 10)

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

# Sicherstellen, dass das Datenverzeichnis existiert
Path(settings.DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
