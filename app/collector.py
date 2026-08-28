"""
FlareHub – Cloudflare Analytics Collector & Zone Actions.

Periodically pulls GraphQL metrics via httpRequests1mGroups from the Cloudflare
Analytics API (https://api.cloudflare.com/client/v4/graphql) and provides
quick-action functions for zone settings (dev mode, purge cache, under attack mode).

Respected Cloudflare platform limits (as of developers.cloudflare.com/analytics/graphql-api/limits):
- GraphQL endpoint: cost-based rate limiting, default quota 300 queries / 5 minutes.
- REST endpoints (zone settings, purge cache): 1200 requests / 5 minutes (global, per user/token).
- A single GraphQL response delivers max. 10,000 records (maxPageSize) – we query
  significantly more conservatively by default (COLLECTOR_MAX_RECORDS_PER_QUERY).
- Free plans have limited access to historical firewall events (e.g. 14 days).
  A 403/permission error from Cloudflare is therefore not treated as a bug, but
  logged in the CollectorRun log as a plan limitation.
"""
import asyncio
import logging
import re
import time
from datetime import datetime, timedelta, timezone

import httpx

from app.config import settings
from app.database import (
    SessionLocal, AnalyticsSnapshot, ThreatEvent, CollectorRun,
    CountryStat, StatusCodeStat, cleanup_old_data,
)

logger = logging.getLogger("flarehub.collector")

# Dataset resolution used at runtime (probed once per process):
# "1m" = httpRequests1mGroups (higher plans), "1h" = httpRequests1hGroups (all plans).
_analytics_resolution: str | None = None

ANALYTICS_QUERY_1M = """
query GetZoneAnalytics($zoneTag: string, $since: Time, $until: Time, $limit: Int) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      httpRequests1mGroups(
        limit: $limit
        filter: { datetime_geq: $since, datetime_leq: $until }
        orderBy: [datetime_ASC]
      ) {
        dimensions { datetime }
        sum {
          requests
          cachedRequests
          bytes
          cachedBytes
          threats
          pageViews
        }
        uniq { uniques }
      }
    }
  }
}
"""

# Hourly fallback dataset - available on ALL plans. Used automatically when the
# zone has no access to httpRequests1mGroups (higher-plan dataset, error:
# "does not have access to the path"). Both nodes return the same
# httpRequestsGroup type, so the arguments mirror ANALYTICS_QUERY_1M exactly.
ANALYTICS_QUERY_1H = """
query GetZoneAnalyticsHourly($zoneTag: string, $since: Time, $until: Time, $limit: Int) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      httpRequests1hGroups(
        limit: $limit
        filter: { datetime_geq: $since, datetime_leq: $until }
        orderBy: [datetime_ASC]
      ) {
        dimensions { datetime }
        sum {
          requests
          cachedRequests
          bytes
          cachedBytes
          threats
          pageViews
        }
        uniq { uniques }
      }
    }
  }
}
"""

FIREWALL_EVENTS_QUERY = """
query GetFirewallEvents($zoneTag: string, $since: Time, $until: Time, $limit: Int) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      firewallEventsAdaptive(
        limit: $limit
        filter: { datetime_geq: $since, datetime_leq: $until }
        orderBy: [datetime_DESC]
      ) {
        datetime
        clientIP
        clientCountryName
        action
        source
        clientRequestPath
        userAgent
      }
    }
  }
}
"""

# Passive analytics (read-only): last 24h, aggregated by origin country and
# HTTP status. Uses httpRequestsAdaptiveGroups - a pure read endpoint,
# no write actions are triggered.
PASSIVE_ANALYTICS_QUERY = """
query GetPassiveAnalytics($zoneTag: string, $since: Time, $until: Time, $limit: Int) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      httpRequestsAdaptiveGroups(
        limit: $limit
        filter: { datetime_geq: $since, datetime_leq: $until }
        orderBy: [count_DESC]
      ) {
        count
        dimensions {
          clientCountryName
          edgeResponseStatus
        }
      }
    }
  }
}
"""


def _headers() -> dict:
    """Rebuild headers on every call so a token changed at runtime takes effect immediately.
    The Authorization header is only set when a token exists - an empty Bearer value
    (f"Bearer " + '') would otherwise cause a LocalProtocolError and an unhandled 500
    in httpx/httpcore."""
    headers = {"Content-Type": "application/json"}
    if settings.CLOUDFLARE_API_TOKEN:
        headers["Authorization"] = f"Bearer {settings.CLOUDFLARE_API_TOKEN}"
    return headers


def _zone_configured() -> tuple[bool, str]:
    """Checks whether the Cloudflare credentials are complete. Returns (ok, error_message)."""
    if not settings.CLOUDFLARE_API_TOKEN or not settings.CLOUDFLARE_ZONE_ID:
        return False, "Cloudflare not configured (set CLOUDFLARE_API_TOKEN / CLOUDFLARE_ZONE_ID in the .env)"
    return True, ""


def _log_run(db, success: bool, message: str, duration_ms: int, records: int = 0):
    db.add(CollectorRun(success=success, message=message, duration_ms=duration_ms, records_fetched=records))
    db.commit()


async def _graphql_request(query: str, variables: dict) -> tuple[dict | None, str | None]:
    """Executes a GraphQL request. Returns (data, error_message) – exactly one of them is None."""
    ok, cfg_error = _zone_configured()
    if not ok:
        return None, cfg_error

    async with httpx.AsyncClient(timeout=settings.CLOUDFLARE_API_TIMEOUT) as client:
        try:
            resp = await client.post(
                settings.CLOUDFLARE_GRAPHQL_URL,
                headers=_headers(),
                json={"query": query, "variables": variables},
            )
        except httpx.TimeoutException:
            return None, "Timeout while contacting Cloudflare"
        except httpx.HTTPError as e:
            return None, f"Network error: {e}"

    if resp.status_code == 429:
        return None, "Cloudflare rate limit reached (429) – will retry on the next interval"
    if resp.status_code == 403:
        return None, "Access denied (403) – check token permissions or plan limits"
    if resp.status_code == 401:
        return None, "Unauthorized (401) – check CLOUDFLARE_API_TOKEN"
    if resp.status_code >= 400:
        return None, f"Cloudflare API error: HTTP {resp.status_code}"

    try:
        payload = resp.json()
    except ValueError:
        return None, "Invalid JSON response from Cloudflare"

    if payload.get("errors"):
        messages = "; ".join(err.get("message", str(err)) for err in payload["errors"])
        return None, f"GraphQL error: {messages}"

    data = payload.get("data")
    if data is None:
        return None, "No data in Cloudflare response"

    return data, None


def _zone_error_hint(error: str) -> str:
    """Augments "zone not found" errors with the configured zone ID so the operator
    can compare it against the Cloudflare dashboard."""
    lowered = error.lower()
    if "zone" in lowered and "not found" in lowered:
        return (
            f"{error} (configured CLOUDFLARE_ZONE_ID: {settings.CLOUDFLARE_ZONE_ID} - "
            f"this ID must belong to the Cloudflare account of the API token; "
            f"copy it from Dashboard -> Overview -> API -> Zone ID)"
        )
    return error


def _is_dataset_access_error(error: str) -> bool:
    """True if Cloudflare denies access to the requested dataset node (plan limitation)."""
    lowered = error.lower()
    return (
        "does not have access to the path" in lowered
        or "not authorized for that account" in lowered
        or "are not authorized" in lowered
    )


def _dataset_access_hint(error: str) -> str:
    if _is_dataset_access_error(error):
        return error + " (this dataset requires a higher Cloudflare plan for the zone)"
    return error


def _current_analytics_query() -> tuple[str, str]:
    """Returns (query, resolution) for the analytics fetch - falls back to the hourly
    dataset when the zone has no access to the 1-minute dataset (plan limit)."""
    global _analytics_resolution
    if _analytics_resolution == "1h":
        return ANALYTICS_QUERY_1H, "1h"
    return ANALYTICS_QUERY_1M, "1m"


def _fallback_to_hourly():
    global _analytics_resolution
    _analytics_resolution = "1h"
    logger.info(
        "Cloudflare zone has no access to httpRequests1mGroups (plan limitation) - "
        "falling back to httpRequests1hGroups (hourly resolution)"
    )


async def _analytics_query_with_fallback(variables: dict) -> tuple[dict | None, str | None, str]:
    """Runs the analytics query with automatic dataset fallback.
    Returns (data, error, resolution)."""
    query, resolution = _current_analytics_query()
    data, error = await _graphql_request(query, variables)
    if error and resolution == "1m" and _is_dataset_access_error(error):
        _fallback_to_hourly()
        query, resolution = _current_analytics_query()
        data, error = await _graphql_request(query, variables)
    return data, error, resolution


async def verify_zone_access() -> dict:
    """Validates token + zone via the same GraphQL query the collector uses (read-only).
    Returns {"configured": bool, "ok": bool, "error": str | None}.

    Using the analytics query keeps the check aligned with what the collector actually
    does – the error message is identical to the one shown in the dashboard banner."""
    ok, cfg_error = _zone_configured()
    if not ok:
        return {"configured": False, "ok": False, "error": cfg_error}

    until = datetime.now(timezone.utc)
    since = until - timedelta(hours=1)

    data, error, _ = await _analytics_query_with_fallback({
        "zoneTag": settings.CLOUDFLARE_ZONE_ID,
        "since": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "until": until.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "limit": 1,
    })
    if error:
        return {"configured": True, "ok": False, "error": _zone_error_hint(error)}
    return {"configured": True, "ok": True, "error": None}


async def fetch_analytics_and_store():
    """Called periodically (COLLECTOR_INTERVAL_MINUTES) by the scheduler."""
    start_ts = time.monotonic()

    ok, cfg_error = _zone_configured()
    if not ok:
        logger.warning("Cloudflare credentials missing (CLOUDFLARE_API_TOKEN / CLOUDFLARE_ZONE_ID) – collector skipped")
        db = SessionLocal()
        try:
            _log_run(db, False, cfg_error, 0)
        finally:
            db.close()
        return

    until = datetime.now(timezone.utc)
    # +1 minute overlap as a buffer against delays in data availability
    since = until - timedelta(minutes=settings.COLLECTOR_INTERVAL_MINUTES + 1)

    variables = {
        "zoneTag": settings.CLOUDFLARE_ZONE_ID,
        "since": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "until": until.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "limit": settings.COLLECTOR_MAX_RECORDS_PER_QUERY,
    }

    data, error, resolution = await _analytics_query_with_fallback(variables)
    duration_ms = int((time.monotonic() - start_ts) * 1000)

    if error:
        error = _zone_error_hint(error)
        logger.error(f"Cloudflare analytics query failed: {error}")
        db = SessionLocal()
        try:
            _log_run(db, False, error, duration_ms)
        finally:
            db.close()
        return

    zones = data.get("viewer", {}).get("zones", [])
    groups = zones[0].get("httpRequests1mGroups", []) if zones else []
    if resolution == "1h":
        groups = zones[0].get("httpRequests1hGroups", []) if zones else []

    records_stored = 0
    if not groups:
        logger.info("No new analytics data in the query window")
    else:
        totals = {
            "requests_total": 0,
            "requests_cached": 0,
            "bandwidth_total_bytes": 0,
            "bandwidth_cached_bytes": 0,
            "threats_total": 0,
            "page_views": 0,
            "unique_visitors": 0,
        }
        for g in groups:
            s = g.get("sum", {})
            totals["requests_total"] += s.get("requests", 0)
            totals["requests_cached"] += s.get("cachedRequests", 0)
            totals["bandwidth_total_bytes"] += s.get("bytes", 0)
            totals["bandwidth_cached_bytes"] += s.get("cachedBytes", 0)
            totals["threats_total"] += s.get("threats", 0)
            totals["page_views"] += s.get("pageViews", 0)
            totals["unique_visitors"] = max(
                totals["unique_visitors"], g.get("uniq", {}).get("uniques", 0)
            )

        if resolution == "1h":
            # Hourly fallback: the API returns the current hour's cumulative total.
            # Store exactly ONE snapshot per hour, otherwise the rollup would sum the
            # same hour multiple times and overcount.
            snapshot_ts = until.replace(tzinfo=None).replace(minute=0, second=0, microsecond=0)
            db = SessionLocal()
            try:
                already_stored = (
                    db.query(AnalyticsSnapshot)
                    .filter(AnalyticsSnapshot.timestamp == snapshot_ts)
                    .first()
                )
                if already_stored:
                    logger.info("Snapshot for the current hour already stored - skipping (hourly fallback)")
                else:
                    db.add(AnalyticsSnapshot(
                        timestamp=snapshot_ts,
                        requests_total=totals["requests_total"],
                        requests_cached=totals["requests_cached"],
                        requests_uncached=totals["requests_total"] - totals["requests_cached"],
                        bandwidth_total_bytes=totals["bandwidth_total_bytes"],
                        bandwidth_cached_bytes=totals["bandwidth_cached_bytes"],
                        bandwidth_uncached_bytes=totals["bandwidth_total_bytes"] - totals["bandwidth_cached_bytes"],
                        threats_total=totals["threats_total"],
                        page_views=totals["page_views"],
                        unique_visitors=totals["unique_visitors"],
                    ))
                    db.commit()
                    records_stored = len(groups)
                    logger.info(
                        f"Analytics snapshot stored: {totals['requests_total']} requests "
                        f"({records_stored} data points, hourly resolution)"
                    )
            finally:
                db.close()
        else:
            db = SessionLocal()
            try:
                db.add(AnalyticsSnapshot(
                    timestamp=until.replace(tzinfo=None),
                    requests_total=totals["requests_total"],
                    requests_cached=totals["requests_cached"],
                    requests_uncached=totals["requests_total"] - totals["requests_cached"],
                    bandwidth_total_bytes=totals["bandwidth_total_bytes"],
                    bandwidth_cached_bytes=totals["bandwidth_cached_bytes"],
                    bandwidth_uncached_bytes=totals["bandwidth_total_bytes"] - totals["bandwidth_cached_bytes"],
                    threats_total=totals["threats_total"],
                    page_views=totals["page_views"],
                    unique_visitors=totals["unique_visitors"],
                ))
                db.commit()
                records_stored = len(groups)
                logger.info(
                    f"Analytics snapshot stored: {totals['requests_total']} requests "
                    f"({records_stored} raw data points)"
                )
            finally:
                db.close()

        # Passive alerting: threat spike in the last interval (only when a new snapshot was stored)
        if (
            records_stored
            and settings.WEBHOOK_ENABLED
            and settings.WEBHOOK_ON_THREAT_SPIKE
            and totals["threats_total"] >= settings.WEBHOOK_THREAT_THRESHOLD
        ):
            await send_webhook_notification(
                f"⚠️ Threat spike detected: {totals['threats_total']} blocked requests in the last interval"
            )

    firewall_records = 0
    firewall_error = None
    if settings.FEATURE_SECURITY_FEED:
        firewall_records, firewall_error = await fetch_firewall_events()

    # Passive analytics (countries & status codes) - read-only, errors are not critical
    passive_records = 0
    passive_error = None
    if settings.FEATURE_COUNTRY_CHART or settings.FEATURE_STATUS_CHART:
        passive_records, passive_error = await fetch_passive_analytics_and_store()

    db = SessionLocal()
    try:
        cleanup_old_data(db)
        notes = []
        if firewall_error:
            notes.append(f"Firewall events skipped: {firewall_error}")
        if passive_error:
            notes.append(f"Passive analytics skipped: {passive_error}")
        if notes:
            _log_run(db, True, "OK (" + "; ".join(notes) + ")", duration_ms, records_stored + firewall_records + passive_records)
        else:
            _log_run(db, True, "OK", duration_ms, records_stored + firewall_records + passive_records)
    finally:
        db.close()


async def fetch_firewall_events() -> tuple[int, str | None]:
    """Fetches firewall/WAF events for the security feed. Returns (stored event count, error)."""
    until = datetime.now(timezone.utc)
    since = until - timedelta(minutes=settings.COLLECTOR_INTERVAL_MINUTES + 1)

    variables = {
        "zoneTag": settings.CLOUDFLARE_ZONE_ID,
        "since": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "until": until.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "limit": min(settings.SECURITY_FEED_LIMIT, settings.COLLECTOR_MAX_RECORDS_PER_QUERY),
    }

    data, error = await _graphql_request(FIREWALL_EVENTS_QUERY, variables)
    if error:
        error = _dataset_access_hint(error)
        logger.warning(f"Cloudflare firewall events query skipped: {error}")
        return 0, error

    zones = data.get("viewer", {}).get("zones", [])
    events = zones[0].get("firewallEventsAdaptive", []) if zones else []

    if not events:
        return 0, None

    db = SessionLocal()
    stored = 0
    try:
        for e in events:
            dt_str = e.get("datetime")
            if not dt_str:
                continue
            try:
                ts = datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                continue
            db.add(ThreatEvent(
                timestamp=ts,
                client_ip=e.get("clientIP"),
                country=e.get("clientCountryName"),
                action=e.get("action"),
                source=e.get("source"),
                path=e.get("clientRequestPath"),
                user_agent=e.get("userAgent"),
            ))
            stored += 1
        db.commit()
        logger.info(f"{stored} firewall events stored")
    finally:
        db.close()

    return stored, None


async def send_webhook_notification(message: str):
    """Sends a notification via the configured webhook (passive, optional).

    WEBHOOK_TYPE: discord (content), telegram (text+chat_id), gotify (message+X-Gotify-Key).
    Errors are logged with the error type only - the exception message contains the
    webhook URL incl. token/secret and must never end up in logs."""
    if not settings.webhook_active:
        return
    webhook_type = settings.WEBHOOK_TYPE
    url = settings.WEBHOOK_URL

    payload: dict = {"content": message}
    headers: dict = {"Content-Type": "application/json"}

    if webhook_type == "telegram":
        chat_id = settings.WEBHOOK_TELEGRAM_CHAT_ID
        if not chat_id:
            from urllib.parse import parse_qs, urlparse

            query = parse_qs(urlparse(url).query)
            chat_id = (query.get("chat_id") or [""])[0]
        if not chat_id:
            logger.warning("Telegram webhook without chat_id - set WEBHOOK_TELEGRAM_CHAT_ID")
            return
        payload = {"chat_id": chat_id, "text": message, "disable_web_page_preview": True}
    elif webhook_type == "gotify":
        payload = {"title": "FlareHub", "message": message, "priority": 5}
        if settings.WEBHOOK_GOTIFY_TOKEN:
            headers["X-Gotify-Key"] = settings.WEBHOOK_GOTIFY_TOKEN

    async with httpx.AsyncClient(timeout=10) as client:
        try:
            await client.post(url, json=payload, headers=headers)
        except httpx.HTTPError as e:
            logger.error("Webhook notification failed (%s)", type(e).__name__)


# ---------------------------------------------------------------------------
# Privacy: IP masking & log scrubbing
# ---------------------------------------------------------------------------
def mask_ip(ip: str) -> str:
    """Masks public IPs: 185.220.xxx.xxx or 2a01:4f8:xxx::
    Invalid/empty values remain unchanged."""
    if not ip:
        return ip
    ip = ip.strip()
    if ":" in ip:  # IPv6
        parts = ip.split(":")
        if len(parts) >= 3:
            return f"{parts[0]}:{parts[1]}:xxx::"
        return ip
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.xxx.xxx"
    return ip


# Patterns for secrets/tokens in log messages - everything is masked as ***
_SECRET_PATTERNS = [
    re.compile(r"(?i)(token|secret|key|passwd|password|authorization|bearer|x-gotify-key)(\s*[=:]\s*)([^\s\"'&]+)"),
    re.compile(r"(?i)(\?|&)(token|key|secret|code|auth)=([^&\s\"']+)"),
    re.compile(r"(https?://[^\s\"']+)"),
]


def scrub_log_message(message: str) -> str:
    """Removes secrets/tokens from log messages (required before display in the log viewer)."""
    if not message:
        return message
    scrubbed = message
    for pattern in _SECRET_PATTERNS:
        if pattern.pattern.endswith(r"(https?://[^\s\"']+)"):
            # Mask URLs completely (they can contain tokens, e.g. webhook URLs)
            scrubbed = pattern.sub("***URL***", scrubbed)
        else:
            scrubbed = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}***", scrubbed)
    return scrubbed


# ---------------------------------------------------------------------------
# Passive analytics: countries & status codes (read-only)
# ---------------------------------------------------------------------------
def _status_group(status) -> str:
    try:
        code = int(status)
    except (TypeError, ValueError):
        return "other"
    if 200 <= code < 300:
        return "2xx"
    if 300 <= code < 400:
        return "3xx"
    if 400 <= code < 500:
        return "4xx"
    if 500 <= code < 600:
        return "5xx"
    return "other"


async def fetch_passive_analytics_and_store() -> tuple[int, str | None]:
    """Fetches the last 24h passively aggregated (origin country + HTTP status) and stores
    them as a snapshot. Returns (stored_row_count, error).

    Read-only - no write DNS/WAF actions are triggered.
    Sends a webhook notification on 5xx threshold breach (optional)."""
    until = datetime.now(timezone.utc)
    since = until - timedelta(hours=24)

    variables = {
        "zoneTag": settings.CLOUDFLARE_ZONE_ID,
        "since": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "until": until.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "limit": settings.COLLECTOR_MAX_RECORDS_PER_QUERY,
    }

    data, error = await _graphql_request(PASSIVE_ANALYTICS_QUERY, variables)
    if error:
        error = _dataset_access_hint(error)
        logger.warning(f"Passive analytics skipped: {error}")
        return 0, error

    zones = data.get("viewer", {}).get("zones", [])
    groups = zones[0].get("httpRequestsAdaptiveGroups", []) if zones else []
    if not groups:
        return 0, None

    period_start = until.replace(tzinfo=None)
    countries: dict[str, int] = {}
    status_groups: dict[str, int] = {}
    for g in groups:
        count = g.get("count", 0) or 0
        dims = g.get("dimensions", {}) or {}
        country = (dims.get("clientCountryName") or "Unknown").strip() or "Unknown"
        countries[country] = countries.get(country, 0) + count
        group = _status_group(dims.get("edgeResponseStatus"))
        status_groups[group] = status_groups.get(group, 0) + count

    db = SessionLocal()
    stored = 0
    try:
        for country, count in sorted(countries.items(), key=lambda item: -item[1]):
            db.add(CountryStat(period_start=period_start, country=country[:64], requests=count))
            stored += 1
        for group, count in sorted(status_groups.items(), key=lambda item: -item[1]):
            db.add(StatusCodeStat(period_start=period_start, status_group=group, requests=count))
            stored += 1
        db.commit()
    finally:
        db.close()

    logger.info(
        f"Passive analytics stored: {len(countries)} countries, "
        f"{len(status_groups)} status groups ({stored} rows)"
    )

    # Passive alerting: 5xx threshold breached
    five_xx = status_groups.get("5xx", 0)
    if (
        settings.WEBHOOK_ENABLED
        and settings.WEBHOOK_ON_5XX
        and five_xx >= settings.WEBHOOK_5XX_THRESHOLD
    ):
        await send_webhook_notification(
            f"🔴 Elevated 5xx errors: {five_xx} in the last 24h "
            f"(threshold: {settings.WEBHOOK_5XX_THRESHOLD})"
        )

    return stored, None


# ---------------------------------------------------------------------------
# Zone quick actions (REST API v4)
# ---------------------------------------------------------------------------
async def set_zone_setting(setting_name: str, value: str) -> tuple[bool, str]:
    """Sets a zone setting, e.g. development_mode or security_level."""
    ok, cfg_error = _zone_configured()
    if not ok:
        return False, cfg_error

    url = f"{settings.CLOUDFLARE_API_BASE_URL}/zones/{settings.CLOUDFLARE_ZONE_ID}/settings/{setting_name}"
    async with httpx.AsyncClient(timeout=settings.CLOUDFLARE_API_TIMEOUT) as client:
        try:
            resp = await client.patch(url, headers=_headers(), json={"value": value})
        except httpx.TimeoutException:
            return False, "Timeout while contacting Cloudflare"
        except httpx.HTTPError as e:
            return False, f"Network error: {e}"

    if resp.status_code == 429:
        return False, "Cloudflare rate limit reached (429), please wait a moment"
    if resp.status_code == 403:
        return False, "Access denied (403) – the token is missing the 'Zone Settings' permission for this zone"

    try:
        data = resp.json()
    except ValueError:
        logger.error(f"Zone setting '{setting_name}' returned invalid JSON (HTTP {resp.status_code})")
        return False, f"Invalid response (HTTP {resp.status_code})"

    if not data.get("success"):
        errors = data.get("errors") or [{"message": f"HTTP {resp.status_code}"}]
        msg = "; ".join(e.get("message", str(e)) for e in errors)
        logger.error(f"Zone setting '{setting_name}' failed (HTTP {resp.status_code}): {msg}")
        return False, msg
    logger.info(f"Zone setting '{setting_name}' updated (HTTP {resp.status_code})")
    return True, "OK"


async def get_zone_setting(setting_name: str) -> str | None:
    ok, _ = _zone_configured()
    if not ok:
        return None

    url = f"{settings.CLOUDFLARE_API_BASE_URL}/zones/{settings.CLOUDFLARE_ZONE_ID}/settings/{setting_name}"
    async with httpx.AsyncClient(timeout=settings.CLOUDFLARE_API_TIMEOUT) as client:
        try:
            resp = await client.get(url, headers=_headers())
            resp.raise_for_status()
            data = resp.json()
            return data.get("result", {}).get("value")
        except httpx.HTTPError as e:
            logger.error(f"Could not read zone setting {setting_name}: {e}")
            return None
        except ValueError as e:
            logger.error(f"Could not read zone setting {setting_name} (invalid response): {e}")
            return None


# Uncritical, readable zone settings for the action center overview
ZONE_SETTINGS_SUMMARY_KEYS = [
    "development_mode",
    "security_level",
    "ssl",
    "min_tls_version",
    "http2",
    "http3",
    "ipv6",
    "brotli",
    "always_online",
    "cache_level",
]


async def get_zone_settings_summary() -> dict:
    """Reads several uncritical zone settings in parallel (read-only)."""
    ok, cfg_error = _zone_configured()
    if not ok:
        return {"configured": False, "error": cfg_error, "settings": {}}

    results = await asyncio.gather(
        *[get_zone_setting(key) for key in ZONE_SETTINGS_SUMMARY_KEYS],
        return_exceptions=True,
    )
    settings_map = {}
    for key, value in zip(ZONE_SETTINGS_SUMMARY_KEYS, results):
        settings_map[key] = None if isinstance(value, Exception) else value
    return {"configured": True, "error": None, "settings": settings_map}


async def purge_cache(purge_everything: bool = True, files: list[str] = None) -> tuple[bool, str]:
    ok, cfg_error = _zone_configured()
    if not ok:
        return False, cfg_error

    url = f"{settings.CLOUDFLARE_API_BASE_URL}/zones/{settings.CLOUDFLARE_ZONE_ID}/purge_cache"
    payload = {"purge_everything": True} if purge_everything else {"files": files or []}
    async with httpx.AsyncClient(timeout=settings.CLOUDFLARE_API_TIMEOUT) as client:
        try:
            resp = await client.post(url, headers=_headers(), json=payload)
        except httpx.TimeoutException:
            return False, "Timeout while contacting Cloudflare"
        except httpx.HTTPError as e:
            return False, f"Network error: {e}"

    if resp.status_code == 429:
        return False, "Cloudflare rate limit reached (429), please wait a moment"
    if resp.status_code == 403:
        return False, "Access denied (403) – the token is missing the 'Cache Purge' permission for this zone"

    try:
        data = resp.json()
    except ValueError:
        logger.error(f"Cache purge returned invalid JSON (HTTP {resp.status_code})")
        return False, f"Invalid response (HTTP {resp.status_code})"

    if not data.get("success"):
        errors = data.get("errors") or [{"message": f"HTTP {resp.status_code}"}]
        msg = "; ".join(e.get("message", str(e)) for e in errors)
        logger.error(f"Cache purge failed (HTTP {resp.status_code}): {msg}")
        return False, msg

    purge_id = (data.get("result") or {}).get("id", "")
    logger.info(f"Cache purge executed (HTTP {resp.status_code}, purge id: {purge_id})")
    if settings.NOTIFY_ON_CACHE_PURGE:
        await send_webhook_notification("🧹 Cache has been purged (FlareHub quick action)")
    return True, "OK"


async def toggle_development_mode(enable: bool) -> tuple[bool, str]:
    return await set_zone_setting("development_mode", "on" if enable else "off")


async def toggle_under_attack_mode(enable: bool) -> tuple[bool, str]:
    value = "under_attack" if enable else "medium"
    ok, msg = await set_zone_setting("security_level", value)
    if ok and settings.NOTIFY_ON_UNDER_ATTACK_TOGGLE:
        state = "enabled" if enable else "disabled"
        await send_webhook_notification(f"🛡️ Under Attack Mode {state} (FlareHub quick action)")
    return ok, msg
