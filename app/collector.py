"""
FlareHub – Cloudflare Analytics Collector & Zone Actions.
Zieht periodisch GraphQL-Metriken und stellt Quick-Action-Funktionen bereit
(Dev Mode, Purge Cache, Under Attack Mode).
"""
import logging
from datetime import datetime, timedelta, timezone

import httpx

from app.config import settings
from app.database import SessionLocal, AnalyticsSnapshot, ThreatEvent, cleanup_old_data

logger = logging.getLogger("flarehub.collector")

HEADERS = {
    "Authorization": f"Bearer {settings.CLOUDFLARE_API_TOKEN}",
    "Content-Type": "application/json",
}

ANALYTICS_QUERY = """
query GetZoneAnalytics($zoneTag: string, $since: Time, $until: Time) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      httpRequests1mGroups(
        limit: 100
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


async def fetch_analytics_and_store():
    """Wird periodisch (COLLECTOR_INTERVAL_MINUTES) vom Scheduler aufgerufen."""
    if not settings.CLOUDFLARE_API_TOKEN or not settings.CLOUDFLARE_ZONE_ID:
        logger.warning("Cloudflare-Zugangsdaten fehlen (CLOUDFLARE_API_TOKEN / CLOUDFLARE_ZONE_ID) – Collector übersprungen")
        return

    until = datetime.now(timezone.utc)
    since = until - timedelta(minutes=settings.COLLECTOR_INTERVAL_MINUTES + 1)

    variables = {
        "zoneTag": settings.CLOUDFLARE_ZONE_ID,
        "since": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "until": until.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    async with httpx.AsyncClient(timeout=settings.CLOUDFLARE_API_TIMEOUT) as client:
        try:
            resp = await client.post(
                settings.CLOUDFLARE_GRAPHQL_URL,
                headers=HEADERS,
                json={"query": ANALYTICS_QUERY, "variables": variables},
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            logger.error(f"Cloudflare Analytics-Abfrage fehlgeschlagen: {e}")
            return

    groups = (
        data.get("data", {})
        .get("viewer", {})
        .get("zones", [{}])[0]
        .get("httpRequests1mGroups", [])
    )

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
            logger.info(f"Analytics-Snapshot gespeichert: {totals['requests_total']} Requests")

            if settings.NOTIFY_WEBHOOK_URL and totals["threats_total"] >= settings.NOTIFY_THREAT_THRESHOLD:
                await send_webhook_notification(
                    f"⚠️ Threat-Spike erkannt: {totals['threats_total']} geblockte Requests im letzten Intervall"
                )
        finally:
            db.close()

    if settings.FEATURE_SECURITY_FEED:
        await fetch_firewall_events()

    db = SessionLocal()
    try:
        cleanup_old_data(db, settings.DATA_RETENTION_DAYS)
    finally:
        db.close()


async def fetch_firewall_events():
    until = datetime.now(timezone.utc)
    since = until - timedelta(minutes=settings.COLLECTOR_INTERVAL_MINUTES + 1)

    variables = {
        "zoneTag": settings.CLOUDFLARE_ZONE_ID,
        "since": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "until": until.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "limit": settings.SECURITY_FEED_LIMIT,
    }

    async with httpx.AsyncClient(timeout=settings.CLOUDFLARE_API_TIMEOUT) as client:
        try:
            resp = await client.post(
                settings.CLOUDFLARE_GRAPHQL_URL,
                headers=HEADERS,
                json={"query": FIREWALL_EVENTS_QUERY, "variables": variables},
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            logger.error(f"Cloudflare Firewall-Events-Abfrage fehlgeschlagen: {e}")
            return

    events = (
        data.get("data", {})
        .get("viewer", {})
        .get("zones", [{}])[0]
        .get("firewallEventsAdaptive", [])
    )

    if not events:
        return

    db = SessionLocal()
    try:
        for e in events:
            db.add(ThreatEvent(
                timestamp=datetime.strptime(e["datetime"], "%Y-%m-%dT%H:%M:%SZ"),
                client_ip=e.get("clientIP"),
                country=e.get("clientCountryName"),
                action=e.get("action"),
                source=e.get("source"),
                path=e.get("clientRequestPath"),
                user_agent=e.get("userAgent"),
            ))
        db.commit()
        logger.info(f"{len(events)} Firewall-Events gespeichert")
    finally:
        db.close()


async def send_webhook_notification(message: str):
    if not settings.NOTIFY_WEBHOOK_URL:
        return
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            await client.post(settings.NOTIFY_WEBHOOK_URL, json={"content": message})
        except Exception as e:
            logger.error(f"Webhook-Benachrichtigung fehlgeschlagen: {e}")


# ---------------------------------------------------------------------------
# Zone Quick Actions
# ---------------------------------------------------------------------------
async def set_zone_setting(setting_name: str, value: str) -> tuple[bool, str]:
    """Setzt ein Zone-Setting, z.B. development_mode oder security_level."""
    url = f"{settings.CLOUDFLARE_API_BASE_URL}/zones/{settings.CLOUDFLARE_ZONE_ID}/settings/{setting_name}"
    async with httpx.AsyncClient(timeout=settings.CLOUDFLARE_API_TIMEOUT) as client:
        try:
            resp = await client.patch(url, headers=HEADERS, json={"value": value})
            resp.raise_for_status()
            data = resp.json()
            if not data.get("success"):
                return False, str(data.get("errors"))
            return True, "OK"
        except Exception as e:
            return False, str(e)


async def get_zone_setting(setting_name: str) -> str | None:
    url = f"{settings.CLOUDFLARE_API_BASE_URL}/zones/{settings.CLOUDFLARE_ZONE_ID}/settings/{setting_name}"
    async with httpx.AsyncClient(timeout=settings.CLOUDFLARE_API_TIMEOUT) as client:
        try:
            resp = await client.get(url, headers=HEADERS)
            resp.raise_for_status()
            data = resp.json()
            return data.get("result", {}).get("value")
        except Exception as e:
            logger.error(f"Konnte Zone-Setting {setting_name} nicht lesen: {e}")
            return None


async def purge_cache(purge_everything: bool = True, files: list[str] = None) -> tuple[bool, str]:
    url = f"{settings.CLOUDFLARE_API_BASE_URL}/zones/{settings.CLOUDFLARE_ZONE_ID}/purge_cache"
    payload = {"purge_everything": True} if purge_everything else {"files": files or []}
    async with httpx.AsyncClient(timeout=settings.CLOUDFLARE_API_TIMEOUT) as client:
        try:
            resp = await client.post(url, headers=HEADERS, json=payload)
            resp.raise_for_status()
            data = resp.json()
            if not data.get("success"):
                return False, str(data.get("errors"))
            if settings.NOTIFY_ON_CACHE_PURGE:
                await send_webhook_notification("🧹 Cache wurde geleert (FlareHub Quick Action)")
            return True, "OK"
        except Exception as e:
            return False, str(e)


async def toggle_development_mode(enable: bool) -> tuple[bool, str]:
    return await set_zone_setting("development_mode", "on" if enable else "off")


async def toggle_under_attack_mode(enable: bool) -> tuple[bool, str]:
    value = "under_attack" if enable else "medium"
    ok, msg = await set_zone_setting("security_level", value)
    if ok and settings.NOTIFY_ON_UNDER_ATTACK_TOGGLE:
        state = "aktiviert" if enable else "deaktiviert"
        await send_webhook_notification(f"🛡️ Under Attack Mode {state} (FlareHub Quick Action)")
    return ok, msg
