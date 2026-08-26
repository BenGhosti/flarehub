"""
FlareHub – Cloudflare Analytics Collector & Zone Actions.

Zieht periodisch GraphQL-Metriken über httpRequests1mGroups von der Cloudflare
Analytics API (https://api.cloudflare.com/client/v4/graphql) und stellt
Quick-Action-Funktionen für Zone-Settings bereit (Dev Mode, Purge Cache,
Under Attack Mode).

Beachtete Cloudflare-Plattform-Limits (Stand: developers.cloudflare.com/analytics/graphql-api/limits):
- GraphQL-Endpunkt: Cost-based Rate-Limiting, Standard-Quota 300 Queries / 5 Minuten.
- REST-Endpunkte (Zone Settings, Purge Cache): 1200 Requests / 5 Minuten (global, pro User/Token).
- Eine einzelne GraphQL-Antwort liefert max. 10.000 Records (maxPageSize) – wir fragen
  standardmäßig deutlich konservativer ab (COLLECTOR_MAX_RECORDS_PER_QUERY).
- Freie Pläne haben nur begrenzten Zugriff auf historische Firewall-Events (u.a. 14 Tage).
  Ein 403/permission-Fehler von Cloudflare wird daher nicht als Bug behandelt, sondern
  im CollectorRun-Log als Plan-Limitierung protokolliert.
"""
import logging
import time
from datetime import datetime, timedelta, timezone

import httpx

from app.config import settings
from app.database import SessionLocal, AnalyticsSnapshot, ThreatEvent, CollectorRun, cleanup_old_data

logger = logging.getLogger("flarehub.collector")

ANALYTICS_QUERY = """
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


def _headers() -> dict:
    """Header bei jedem Call neu bauen, damit ein zur Laufzeit geänderter Token sofort greift."""
    return {
        "Authorization": f"Bearer {settings.CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json",
    }


def _log_run(db, success: bool, message: str, duration_ms: int, records: int = 0):
    db.add(CollectorRun(success=success, message=message, duration_ms=duration_ms, records_fetched=records))
    db.commit()


async def _graphql_request(query: str, variables: dict) -> tuple[dict | None, str | None]:
    """Führt eine GraphQL-Anfrage aus. Gibt (data, error_message) zurück – genau eines ist None."""
    async with httpx.AsyncClient(timeout=settings.CLOUDFLARE_API_TIMEOUT) as client:
        try:
            resp = await client.post(
                settings.CLOUDFLARE_GRAPHQL_URL,
                headers=_headers(),
                json={"query": query, "variables": variables},
            )
        except httpx.TimeoutException:
            return None, "Zeitüberschreitung bei Cloudflare-Anfrage"
        except httpx.RequestError as e:
            return None, f"Netzwerkfehler: {e}"

    if resp.status_code == 429:
        return None, "Cloudflare Rate-Limit erreicht (429) – nächster Versuch beim nächsten Intervall"
    if resp.status_code == 403:
        return None, "Zugriff verweigert (403) – Token-Berechtigung oder Plan-Limit prüfen"
    if resp.status_code == 401:
        return None, "Nicht autorisiert (401) – CLOUDFLARE_API_TOKEN prüfen"
    if resp.status_code >= 400:
        return None, f"Cloudflare-API-Fehler: HTTP {resp.status_code}"

    try:
        payload = resp.json()
    except ValueError:
        return None, "Ungültige JSON-Antwort von Cloudflare"

    if payload.get("errors"):
        messages = "; ".join(err.get("message", str(err)) for err in payload["errors"])
        return None, f"GraphQL-Fehler: {messages}"

    data = payload.get("data")
    if data is None:
        return None, "Keine Daten in Cloudflare-Antwort"

    return data, None


async def fetch_analytics_and_store():
    """Wird periodisch (COLLECTOR_INTERVAL_MINUTES) vom Scheduler aufgerufen."""
    start_ts = time.monotonic()

    if not settings.CLOUDFLARE_API_TOKEN or not settings.CLOUDFLARE_ZONE_ID:
        logger.warning("Cloudflare-Zugangsdaten fehlen (CLOUDFLARE_API_TOKEN / CLOUDFLARE_ZONE_ID) – Collector übersprungen")
        db = SessionLocal()
        try:
            _log_run(db, False, "Zugangsdaten fehlen (Token/Zone-ID)", 0)
        finally:
            db.close()
        return

    until = datetime.now(timezone.utc)
    # +1 Minute Überlappung als Puffer gegen Verzögerungen bei der Datenverfügbarkeit
    since = until - timedelta(minutes=settings.COLLECTOR_INTERVAL_MINUTES + 1)

    variables = {
        "zoneTag": settings.CLOUDFLARE_ZONE_ID,
        "since": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "until": until.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "limit": settings.COLLECTOR_MAX_RECORDS_PER_QUERY,
    }

    data, error = await _graphql_request(ANALYTICS_QUERY, variables)
    duration_ms = int((time.monotonic() - start_ts) * 1000)

    if error:
        logger.error(f"Cloudflare Analytics-Abfrage fehlgeschlagen: {error}")
        db = SessionLocal()
        try:
            _log_run(db, False, error, duration_ms)
        finally:
            db.close()
        return

    zones = data.get("viewer", {}).get("zones", [])
    groups = zones[0].get("httpRequests1mGroups", []) if zones else []

    records_stored = 0
    if not groups:
        logger.info("Keine neuen Analytics-Daten im Abfragezeitraum")
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

        db = SessionLocal()
        try:
            snapshot = AnalyticsSnapshot(
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
            )
            db.add(snapshot)
            db.commit()
            records_stored = len(groups)
            logger.info(f"Analytics-Snapshot gespeichert: {totals['requests_total']} Requests ({records_stored} Rohdatenpunkte)")

            if settings.NOTIFY_WEBHOOK_URL and totals["threats_total"] >= settings.NOTIFY_THREAT_THRESHOLD:
                await send_webhook_notification(
                    f"⚠️ Threat-Spike erkannt: {totals['threats_total']} geblockte Requests im letzten Intervall"
                )
        finally:
            db.close()

    firewall_records = 0
    firewall_error = None
    if settings.FEATURE_SECURITY_FEED:
        firewall_records, firewall_error = await fetch_firewall_events()

    db = SessionLocal()
    try:
        cleanup_old_data(db)
        if firewall_error:
            _log_run(db, True, f"OK (Firewall-Events übersprungen: {firewall_error})", duration_ms, records_stored)
        else:
            _log_run(db, True, "OK", duration_ms, records_stored + firewall_records)
    finally:
        db.close()


async def fetch_firewall_events() -> tuple[int, str | None]:
    """Holt Firewall/WAF-Events für den Security-Feed. Gibt (Anzahl gespeicherter Events, Fehler) zurück."""
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
        logger.warning(f"Cloudflare Firewall-Events-Abfrage übersprungen: {error}")
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
        logger.info(f"{stored} Firewall-Events gespeichert")
    finally:
        db.close()

    return stored, None


async def send_webhook_notification(message: str):
    if not settings.NOTIFY_WEBHOOK_URL:
        return
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            await client.post(settings.NOTIFY_WEBHOOK_URL, json={"content": message})
        except httpx.RequestError as e:
            logger.error(f"Webhook-Benachrichtigung fehlgeschlagen: {e}")


# ---------------------------------------------------------------------------
# Zone Quick Actions (REST API v4)
# ---------------------------------------------------------------------------
async def set_zone_setting(setting_name: str, value: str) -> tuple[bool, str]:
    """Setzt ein Zone-Setting, z.B. development_mode oder security_level."""
    url = f"{settings.CLOUDFLARE_API_BASE_URL}/zones/{settings.CLOUDFLARE_ZONE_ID}/settings/{setting_name}"
    async with httpx.AsyncClient(timeout=settings.CLOUDFLARE_API_TIMEOUT) as client:
        try:
            resp = await client.patch(url, headers=_headers(), json={"value": value})
        except httpx.RequestError as e:
            return False, f"Netzwerkfehler: {e}"

    if resp.status_code == 429:
        return False, "Cloudflare Rate-Limit erreicht (429), bitte kurz warten"
    if resp.status_code == 403:
        return False, "Zugriff verweigert (403) – Token-Berechtigung 'Zone Settings: Edit' prüfen"

    try:
        data = resp.json()
    except ValueError:
        return False, f"Ungültige Antwort (HTTP {resp.status_code})"

    if not data.get("success"):
        errors = data.get("errors") or [{"message": f"HTTP {resp.status_code}"}]
        return False, "; ".join(e.get("message", str(e)) for e in errors)
    return True, "OK"


async def get_zone_setting(setting_name: str) -> str | None:
    url = f"{settings.CLOUDFLARE_API_BASE_URL}/zones/{settings.CLOUDFLARE_ZONE_ID}/settings/{setting_name}"
    async with httpx.AsyncClient(timeout=settings.CLOUDFLARE_API_TIMEOUT) as client:
        try:
            resp = await client.get(url, headers=_headers())
            resp.raise_for_status()
            data = resp.json()
            return data.get("result", {}).get("value")
        except (httpx.RequestError, httpx.HTTPStatusError, ValueError) as e:
            logger.error(f"Konnte Zone-Setting {setting_name} nicht lesen: {e}")
            return None


async def purge_cache(purge_everything: bool = True, files: list[str] = None) -> tuple[bool, str]:
    url = f"{settings.CLOUDFLARE_API_BASE_URL}/zones/{settings.CLOUDFLARE_ZONE_ID}/purge_cache"
    payload = {"purge_everything": True} if purge_everything else {"files": files or []}
    async with httpx.AsyncClient(timeout=settings.CLOUDFLARE_API_TIMEOUT) as client:
        try:
            resp = await client.post(url, headers=_headers(), json=payload)
        except httpx.RequestError as e:
            return False, f"Netzwerkfehler: {e}"

    if resp.status_code == 429:
        return False, "Cloudflare Rate-Limit erreicht (429), bitte kurz warten"
    if resp.status_code == 403:
        return False, "Zugriff verweigert (403) – Token-Berechtigung 'Cache Purge: Edit' prüfen"

    try:
        data = resp.json()
    except ValueError:
        return False, f"Ungültige Antwort (HTTP {resp.status_code})"

    if not data.get("success"):
        errors = data.get("errors") or [{"message": f"HTTP {resp.status_code}"}]
        return False, "; ".join(e.get("message", str(e)) for e in errors)

    if settings.NOTIFY_ON_CACHE_PURGE:
        await send_webhook_notification("🧹 Cache wurde geleert (FlareHub Quick Action)")
    return True, "OK"


async def toggle_development_mode(enable: bool) -> tuple[bool, str]:
    return await set_zone_setting("development_mode", "on" if enable else "off")


async def toggle_under_attack_mode(enable: bool) -> tuple[bool, str]:
    value = "under_attack" if enable else "medium"
    ok, msg = await set_zone_setting("security_level", value)
    if ok and settings.NOTIFY_ON_UNDER_ATTACK_TOGGLE:
        state = "aktiviert" if enable else "deaktiviert"
        await send_webhook_notification(f"🛡️ Under Attack Mode {state} (FlareHub Quick Action)")
    return ok, msg
