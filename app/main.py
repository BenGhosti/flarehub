"""
FlareHub – Cloudflare Analytics & Quick Actions Dashboard.
FastAPI backend with Jinja2 templates, WebAuthn/PIN auth and Cloudflare GraphQL analytics.
"""
import logging
import time
from collections import Counter
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from urllib.parse import urlparse

from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from app.config import settings
from app.database import (
    init_db, get_db, SessionLocal,
    AnalyticsSnapshot, AnalyticsHourly, AnalyticsDaily, ThreatEvent, LoginAttempt, CollectorRun,
    WebAuthnCredential, CountryStat, StatusCodeStat, ContentTypeStat, TopUrlStat,
    get_storage_stats, db_maintenance,
)
from app import auth
from app import collector

logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL, logging.INFO))
logger = logging.getLogger("flarehub")

scheduler = AsyncIOScheduler()

# Simple in-memory rate limiter for login endpoints
_rate_limit_buckets: dict = {}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    if not settings.auth_disabled:
        logger.info(f"Auth mode: {settings.AUTH_MODE}")
    else:
        logger.warning("AUTH_MODE=none – dashboard is UNPROTECTED!")

    if settings.SESSION_SECRET_KEY == "change-me-to-a-long-random-string":
        logger.warning("SESSION_SECRET_KEY is still the default value – please set a random string in the .env!")

    # Zone/token diagnostic check at startup (non-fatal, read-only).
    zone_check = await collector.verify_zone_access()
    if not zone_check["configured"]:
        logger.warning(
            "Cloudflare not configured (CLOUDFLARE_API_TOKEN / CLOUDFLARE_ZONE_ID) – "
            "the collector will skip runs until they are set in the .env"
        )
    elif not zone_check["ok"]:
        logger.error(
            f"Cloudflare zone/token check FAILED: {zone_check['error']} – "
            f"fix CLOUDFLARE_ZONE_ID / CLOUDFLARE_API_TOKEN in the .env"
        )
    else:
        logger.info(f"Cloudflare zone/token check OK (zone {settings.CLOUDFLARE_ZONE_ID})")

    scheduler.add_job(
        collector.fetch_analytics_and_store,
        "interval",
        minutes=settings.COLLECTOR_INTERVAL_MINUTES,
        id="analytics_collector",
        next_run_time=datetime.now() if settings.COLLECTOR_RUN_ON_STARTUP else None,
    )
    scheduler.start()
    logger.info(f"{settings.APP_NAME} started – collector interval: {settings.COLLECTOR_INTERVAL_MINUTES}min")
    yield
    scheduler.shutdown()


app = FastAPI(title=settings.APP_NAME, lifespan=lifespan)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


@app.middleware("http")
async def csrf_origin_check(request: Request, call_next):
    """Lightweight CSRF protection for state-changing requests.

    For POST/PUT/PATCH/DELETE it checks that a sent Origin header matches the
    Host header (same origin). Requests without an Origin header (curl, server-to-server)
    remain allowed. Together with the stateless Bearer token this prevents cross-site
    requests against quick actions / passkey management."""

    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = request.headers.get("origin")
        if origin:
            host = request.headers.get("host", "")
            try:
                origin_host = urlparse(origin).netloc
            except ValueError:
                origin_host = ""
            if origin_host and origin_host != host:
                return JSONResponse(status_code=403, content={"detail": "Cross-Origin request rejected"})
    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Sets security headers on all responses (disable via .env).

    - CSP: only own resources (inline scripts/styles allowed, no external origins)
    - X-Frame-Options: DENY against clickjacking
    - X-Content-Type-Options: nosniff against MIME sniffing
    - Referrer-Policy: no-referrer (no leaks to third-party pages)"""
    response = await call_next(request)
    if settings.SECURITY_HEADERS_ENABLED:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'",
        )
    return response


@app.middleware("http")
async def no_store_cache(request: Request, call_next):
    """Prevents browser caching of authenticated content (pages + APIs).

    /static assets may be cached, everything else gets Cache-Control: no-store.
    Disable via HTTP_CACHE_NO_STORE=false in the .env."""
    response = await call_next(request)
    if settings.HTTP_CACHE_NO_STORE and not request.url.path.startswith("/static"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


def _rate_limit_ok(ip: str) -> bool:
    if not settings.RATE_LIMIT_ENABLED:
        return True
    now = time.time()
    window = _rate_limit_buckets.setdefault(ip, [])
    window[:] = [t for t in window if now - t < 60]
    if len(window) >= settings.RATE_LIMIT_LOGIN_ATTEMPTS_PER_MINUTE:
        return False
    window.append(now)
    return True


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------
class PinPayload(BaseModel):
    pin: str


class PasskeyVerifyPayload(BaseModel):
    credential: dict


class RegisterVerifyPayload(BaseModel):
    credential: dict
    nickname: str | None = None


class AdminTokenPayload(BaseModel):
    token: str


@app.get("/api/auth/status")
async def auth_status(request: Request, db: Session = Depends(get_db)):
    authenticated = False
    if settings.auth_disabled:
        authenticated = True
    else:
        token = auth.extract_bearer_token(request)
        if token:
            authenticated = auth.verify_access_token(token)

    has_passkeys = db.query(WebAuthnCredential).count() > 0

    return {
        "authenticated": authenticated,
        "required": not settings.auth_disabled,
        "auth_mode": settings.AUTH_MODE,
        "pin_enabled": settings.auth_pin_enabled,
        "passkey_enabled": settings.auth_passkey_enabled,
        "has_passkeys": has_passkeys,
        "pin_length": settings.AUTH_PIN_LENGTH,
        "app_name": settings.APP_NAME,
    }


@app.post("/api/auth/verify-pin")
async def verify_pin_endpoint(payload: PinPayload, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if not _rate_limit_ok(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests. Please wait a moment.")

    ok, message = auth.verify_pin(payload.pin, client_ip)

    db = SessionLocal()
    try:
        db.add(LoginAttempt(method="pin", success=ok, ip_address=client_ip))
        db.commit()
    finally:
        db.close()

    if not ok:
        raise HTTPException(status_code=401, detail=message)

    # No cookie: return a short signed token, the frontend stores it in the
    # sessionStorage and sends it as a Bearer header.
    return {"success": True, "token": auth.create_access_token()}


@app.post("/api/passkey/auth-options")
async def passkey_auth_options(db: Session = Depends(get_db)):
    if not settings.auth_passkey_enabled:
        raise HTTPException(status_code=403, detail="Passkey login is disabled")
    options_json = auth.build_authentication_options(db)
    return JSONResponse(content=options_json, media_type="application/json")


@app.post("/api/passkey/auth-verify")
async def passkey_auth_verify(payload: PasskeyVerifyPayload, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    if not _rate_limit_ok(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests. Please wait a moment.")

    ok, message = auth.verify_passkey_authentication(db, payload.credential)

    db.add(LoginAttempt(method="passkey", success=ok, ip_address=client_ip))
    db.commit()

    if not ok:
        raise HTTPException(status_code=401, detail=message)

    return {"success": True, "token": auth.create_access_token()}


def require_admin_grant(request: Request) -> bool:
    """Dependency: requires a valid admin token grant in addition to the login token.
    Protects passkey management (add/delete) separately from the normal login."""
    auth.get_current_session(request)
    grant = request.headers.get("x-admin-grant", "")
    if not grant or not auth.verify_admin_token_grant(grant):
        raise HTTPException(status_code=403, detail="Admin token required")
    return True


@app.post("/api/admin/verify")
async def admin_verify(payload: AdminTokenPayload, request: Request):
    """Checks the admin token from the .env and issues a short-lived grant on success.
    The grant is NOT cached: it is valid for 10 minutes only and lives exclusively
    in the browser's sessionStorage."""
    auth.get_current_session(request)
    client_ip = request.client.host if request.client else "unknown"
    if not _rate_limit_ok(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests. Please wait a moment.")

    ok, message = auth.verify_admin_token(payload.token, client_ip)
    if not ok:
        raise HTTPException(status_code=403, detail=message)

    return {"success": True, "grant": auth.create_admin_token_grant()}


@app.get("/api/admin/status")
async def admin_status(request: Request):
    auth.get_current_session(request)
    grant = request.headers.get("x-admin-grant", "")
    unlocked = bool(grant and auth.verify_admin_token_grant(grant))
    reveal = request.headers.get("x-reveal-ips", "") == "1"
    return {
        "admin_unlocked": unlocked,
        # Masking is active unless temporarily disabled via the admin grant
        "mask_ips": bool(settings.MASK_IPS_IN_FEED) and not (unlocked and reveal),
        "mask_ips_configured": bool(settings.MASK_IPS_IN_FEED),
        "webhook_enabled": settings.WEBHOOK_ENABLED,
        "webhook_type": settings.WEBHOOK_TYPE if settings.WEBHOOK_ENABLED else None,
    }


@app.get("/api/admin/logs")
async def admin_logs(
    _admin: bool = Depends(require_admin_grant),
    db: Session = Depends(get_db),
    limit: int = 50,
):
    """Read-only log viewer: recent collector runs. Secrets/tokens are always masked
    as *** before the messages leave the API."""
    limit = max(1, min(limit, 200))
    rows = (
        db.query(CollectorRun)
        .order_by(desc(CollectorRun.timestamp))
        .limit(limit)
        .all()
    )
    return [
        {
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "success": r.success,
            "message": collector.scrub_log_message(r.message),
            "duration_ms": r.duration_ms,
            "records_fetched": r.records_fetched,
        }
        for r in rows
    ]


@app.post("/api/admin/db-maintenance")
async def admin_db_maintenance(_admin: bool = Depends(require_admin_grant)):
    """Manual SQLite maintenance: VACUUM (compacts) + ANALYZE (statistics)."""
    return db_maintenance()


@app.post("/api/passkey/register-options")
async def passkey_register_options(_admin: bool = Depends(require_admin_grant), db: Session = Depends(get_db)):
    """Protected by session + admin token grant. Starts the registration of a new passkey."""
    options_json = auth.build_registration_options(db)
    return JSONResponse(content=options_json, media_type="application/json")


@app.post("/api/passkey/register-verify")
async def passkey_register_verify(
    payload: RegisterVerifyPayload,
    _admin: bool = Depends(require_admin_grant),
    db: Session = Depends(get_db),
):
    ok, message = auth.store_new_credential(db, payload.credential, payload.nickname)
    if not ok:
        raise HTTPException(status_code=400, detail=message)
    return {"success": True}


@app.get("/api/passkey/list")
async def passkey_list(_admin: bool = Depends(require_admin_grant), db: Session = Depends(get_db)):
    return auth.list_credentials(db)


@app.delete("/api/passkey/{credential_row_id}")
async def passkey_delete(
    credential_row_id: int,
    _admin: bool = Depends(require_admin_grant),
    db: Session = Depends(get_db),
):
    ok, message = auth.delete_credential(db, credential_row_id)
    if not ok:
        raise HTTPException(status_code=404, detail=message)
    return {"success": True}


@app.post("/api/auth/logout")
async def logout():
    """Stateless logout: there is nothing to delete server-side (no cookie, no
    server session store). The frontend discards the token from the sessionStorage."""
    return {"success": True}


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if settings.auth_disabled:
        return RedirectResponse(url="/")
    return templates.TemplateResponse(request, "login.html", {
        "app_name": settings.APP_NAME,
        "auth_mode": settings.AUTH_MODE,
        "pin_length": settings.AUTH_PIN_LENGTH,
        "default_theme": settings.DEFAULT_THEME,
    })


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    # The page skeleton contains no sensitive data (all data comes via the API with
    # a Bearer token). The token check happens in the frontend:
    # Without a valid token, the page immediately redirects to /login.
    return templates.TemplateResponse(request, "settings.html", {
        "app_name": settings.APP_NAME,
        "default_theme": settings.DEFAULT_THEME,
        "admin_token_configured": bool(settings.ADMIN_TOKEN),
        "auth_required": not settings.auth_disabled,
        "active_page": "settings",
        "feature_action_center": settings.FEATURE_ACTION_CENTER,
    })


@app.get("/actions", response_class=HTMLResponse)
async def actions_page(request: Request):
    if not settings.FEATURE_ACTION_CENTER:
        return RedirectResponse(url="/")
    return templates.TemplateResponse(request, "actions.html", {
        "app_name": settings.APP_NAME,
        "default_theme": settings.DEFAULT_THEME,
        "auth_required": not settings.auth_disabled,
        "feature_purge_cache": settings.FEATURE_PURGE_CACHE,
        "zone_configured": bool(settings.CLOUDFLARE_API_TOKEN and settings.CLOUDFLARE_ZONE_ID),
        "active_page": "actions",
        "feature_action_center": settings.FEATURE_ACTION_CENTER,
    })


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    """Dedicated admin view: passkey management, DB tools, log viewer, privacy.
    All admin APIs require the ADMIN_TOKEN (grant in the sessionStorage)."""
    return templates.TemplateResponse(request, "admin.html", {
        "app_name": settings.APP_NAME,
        "default_theme": settings.DEFAULT_THEME,
        "auth_required": not settings.auth_disabled,
        "admin_token_configured": bool(settings.ADMIN_TOKEN),
        "active_page": "admin",
        "feature_action_center": settings.FEATURE_ACTION_CENTER,
    })


@app.get("/", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    return templates.TemplateResponse(request, "dashboard.html", {
        "app_name": settings.APP_NAME,
        "default_theme": settings.DEFAULT_THEME,
        "auth_required": not settings.auth_disabled,
        "feature_requests_chart": settings.FEATURE_REQUESTS_CHART,
        "feature_bandwidth_chart": settings.FEATURE_BANDWIDTH_CHART,
        "feature_cache_ratio_chart": settings.FEATURE_CACHE_RATIO_CHART,
        "feature_threats_chart": settings.FEATURE_THREATS_CHART,
        "feature_security_feed": settings.FEATURE_SECURITY_FEED,
        "feature_cache_donut_chart": settings.FEATURE_CACHE_DONUT_CHART,
        "feature_threat_donut_chart": settings.FEATURE_THREAT_DONUT_CHART,
        "feature_visitors_chart": settings.FEATURE_VISITORS_CHART,
        "feature_pageviews_chart": settings.FEATURE_PAGEVIEWS_CHART,
        "feature_cached_uncached_chart": settings.FEATURE_CACHED_UNCACHED_CHART,
        "feature_country_chart": settings.FEATURE_COUNTRY_CHART,
        "feature_status_chart": settings.FEATURE_STATUS_CHART,
        "feature_action_center": settings.FEATURE_ACTION_CENTER,
        "feature_quick_actions": settings.FEATURE_QUICK_ACTIONS,
        "feature_dev_mode_toggle": settings.FEATURE_DEV_MODE_TOGGLE,
        "feature_purge_cache": settings.FEATURE_PURGE_CACHE,
        "feature_under_attack_toggle": settings.FEATURE_UNDER_ATTACK_TOGGLE,
        "auto_refresh_seconds": settings.DASHBOARD_AUTO_REFRESH_SECONDS,
        "zone_configured": bool(settings.CLOUDFLARE_API_TOKEN and settings.CLOUDFLARE_ZONE_ID),
        "active_page": "dashboard",
        "feature_action_center": settings.FEATURE_ACTION_CENTER,
    })


# ---------------------------------------------------------------------------
# Analytics data API
# ---------------------------------------------------------------------------
@app.get("/api/analytics/timeseries")
async def analytics_timeseries(
    range: str = "24h",
    _auth: bool = Depends(auth.get_current_session),
    db: Session = Depends(get_db),
):
    """Returns time series data for the selected period. Automatically picks the matching
    resolution: short periods use raw data (10-minute resolution), long periods use the
    hourly/daily rollups, so the response stays small and old data remains visible
    despite compaction."""
    now = datetime.utcnow()
    range_map = {
        "6h": (timedelta(hours=6), "raw"),
        "24h": (timedelta(hours=24), "raw"),
        "7d": (timedelta(days=7), "hourly"),
        "30d": (timedelta(days=30), "hourly"),
        "90d": (timedelta(days=90), "daily"),
        "1y": (timedelta(days=365), "daily"),
    }
    delta, resolution = range_map.get(range, range_map["24h"])
    since = now - delta

    labels, req_total, req_cached, req_uncached = [], [], [], []
    bw_total, bw_cached, threats, uniques, page_views = [], [], [], [], []

    if resolution == "raw":
        # Raw data only covers the last RAW_RETENTION_HOURS; older points in the
        # selected window come from the hourly rollups, so e.g. in the 24h view no
        # gap appears shortly after a compaction run.
        raw_rows = (
            db.query(AnalyticsSnapshot)
            .filter(AnalyticsSnapshot.timestamp >= since)
            .order_by(AnalyticsSnapshot.timestamp.asc())
            .limit(settings.CHART_DEFAULT_DATAPOINTS)
            .all()
        )
        oldest_raw = raw_rows[0].timestamp if raw_rows else now
        hourly_rows = (
            db.query(AnalyticsHourly)
            .filter(AnalyticsHourly.hour_start >= since, AnalyticsHourly.hour_start < oldest_raw)
            .order_by(AnalyticsHourly.hour_start.asc())
            .all()
        )
        for r in hourly_rows:
            labels.append(r.hour_start.strftime("%Y-%m-%d %H:%M"))
            req_total.append(r.requests_total)
            req_cached.append(r.requests_cached)
            req_uncached.append(r.requests_uncached)
            bw_total.append(round(r.bandwidth_total_bytes / 1_000_000, 2))
            bw_cached.append(round(r.bandwidth_cached_bytes / 1_000_000, 2))
            threats.append(r.threats_total)
            uniques.append(r.unique_visitors_max)
            page_views.append(r.page_views)
        for r in raw_rows:
            labels.append(r.timestamp.strftime("%Y-%m-%d %H:%M"))
            req_total.append(r.requests_total)
            req_cached.append(r.requests_cached)
            req_uncached.append(r.requests_uncached)
            bw_total.append(round(r.bandwidth_total_bytes / 1_000_000, 2))
            bw_cached.append(round(r.bandwidth_cached_bytes / 1_000_000, 2))
            threats.append(r.threats_total)
            uniques.append(r.unique_visitors)
            page_views.append(r.page_views)

    elif resolution == "hourly":
        rows = (
            db.query(AnalyticsHourly)
            .filter(AnalyticsHourly.hour_start >= since)
            .order_by(AnalyticsHourly.hour_start.asc())
            .limit(settings.CHART_DEFAULT_DATAPOINTS)
            .all()
        )
        for r in rows:
            labels.append(r.hour_start.strftime("%Y-%m-%d %H:%M"))
            req_total.append(r.requests_total)
            req_cached.append(r.requests_cached)
            req_uncached.append(r.requests_uncached)
            bw_total.append(round(r.bandwidth_total_bytes / 1_000_000, 2))
            bw_cached.append(round(r.bandwidth_cached_bytes / 1_000_000, 2))
            threats.append(r.threats_total)
            uniques.append(r.unique_visitors_max)
            page_views.append(r.page_views)

    else:  # daily
        rows = (
            db.query(AnalyticsDaily)
            .filter(AnalyticsDaily.day >= since)
            .order_by(AnalyticsDaily.day.asc())
            .limit(settings.CHART_DEFAULT_DATAPOINTS)
            .all()
        )
        for r in rows:
            labels.append(r.day.strftime("%Y-%m-%d"))
            req_total.append(r.requests_total)
            req_cached.append(r.requests_cached)
            req_uncached.append(r.requests_uncached)
            bw_total.append(round(r.bandwidth_total_bytes / 1_000_000, 2))
            bw_cached.append(round(r.bandwidth_cached_bytes / 1_000_000, 2))
            threats.append(r.threats_total)
            uniques.append(r.unique_visitors_max)
            page_views.append(r.page_views)

    return {
        "resolution": resolution,
        "labels": labels,
        "requests_total": req_total,
        "requests_cached": req_cached,
        "requests_uncached": req_uncached,
        "bandwidth_total_mb": bw_total,
        "bandwidth_cached_mb": bw_cached,
        "threats_total": threats,
        "unique_visitors": uniques,
        "page_views": page_views,
    }


@app.get("/api/analytics/donuts")
async def analytics_donuts(
    range: str = "24h",
    _auth: bool = Depends(auth.get_current_session),
    db: Session = Depends(get_db),
):
    """Aggregated values for the donut charts (cache split + threat actions) over the
    selected period."""
    now = datetime.utcnow()
    range_map = {
        "6h": (timedelta(hours=6), "raw"),
        "24h": (timedelta(hours=24), "raw"),
        "7d": (timedelta(days=7), "hourly"),
        "30d": (timedelta(days=30), "hourly"),
        "90d": (timedelta(days=90), "daily"),
        "1y": (timedelta(days=365), "daily"),
    }
    delta, resolution = range_map.get(range, range_map["24h"])
    since = now - delta

    if resolution == "raw":
        rows = db.query(AnalyticsSnapshot).filter(AnalyticsSnapshot.timestamp >= since).all()
    elif resolution == "hourly":
        rows = db.query(AnalyticsHourly).filter(AnalyticsHourly.hour_start >= since).all()
    else:
        rows = db.query(AnalyticsDaily).filter(AnalyticsDaily.day >= since).all()

    cached = sum(r.requests_cached for r in rows)
    uncached = sum(r.requests_uncached for r in rows)

    # Threat actions from the individual feed events. Only available as long as the
    # events are not deleted by the retention (THREAT_EVENT_RETENTION_DAYS) - for long
    # periods this is therefore a subset of the aggregated threats.
    action_counts: dict[str, int] = {}
    event_rows = db.query(ThreatEvent).filter(ThreatEvent.timestamp >= since).all()
    for e in event_rows:
        action = (e.action or "unknown").lower()
        action_counts[action] = action_counts.get(action, 0) + 1

    return {
        "cache": {"cached": cached, "uncached": uncached},
        "threat_actions": [
            {"action": action, "count": count}
            for action, count in sorted(action_counts.items(), key=lambda item: -item[1])
        ],
        "threat_events_available": len(event_rows) > 0,
    }


@app.get("/api/analytics/countries")
async def analytics_countries(
    _auth: bool = Depends(auth.get_current_session),
    db: Session = Depends(get_db),
):
    """Top origin countries from the latest passive analytics snapshot (last 24h).
    Returns the top 10 plus an 'Other' bucket for the donut chart."""
    latest = db.query(CountryStat).order_by(desc(CountryStat.period_start)).first()
    if not latest:
        return {"available": False, "countries": [], "period_start": None}

    rows = (
        db.query(CountryStat)
        .filter(CountryStat.period_start == latest.period_start)
        .order_by(desc(CountryStat.requests))
        .all()
    )
    countries = []
    other = 0
    for r in rows:
        if len(countries) < 10:
            countries.append({"country": r.country, "requests": r.requests})
        else:
            other += r.requests
    if other > 0:
        countries.append({"country": "Other", "requests": other})

    return {
        "available": True,
        "countries": countries,
        "period_start": latest.period_start.isoformat(),
    }


@app.get("/api/analytics/status-codes")
async def analytics_status_codes(
    _auth: bool = Depends(auth.get_current_session),
    db: Session = Depends(get_db),
):
    """HTTP status code groups (2xx/3xx/4xx/5xx) from the latest passive snapshot."""
    latest = db.query(StatusCodeStat).order_by(desc(StatusCodeStat.period_start)).first()
    if not latest:
        return {"available": False, "groups": []}

    rows = (
        db.query(StatusCodeStat)
        .filter(StatusCodeStat.period_start == latest.period_start)
        .order_by(desc(StatusCodeStat.requests))
        .all()
    )
    order = ["2xx", "3xx", "4xx", "5xx"]
    by_group = {r.status_group: r.requests for r in rows}
    return {
        "available": True,
        "groups": [{"group": g, "requests": by_group.get(g, 0)} for g in order],
    }


@app.get("/api/analytics/extras")
async def analytics_extras(
    _auth: bool = Depends(auth.get_current_session),
    db: Session = Depends(get_db),
):
    """Extended passive analytics: content type split (7d), country trend (30d),
    status trend (30d) and top URLs (latest 24h snapshot). Read-only aggregations
    of the stored snapshots - no extra Cloudflare fetch."""
    now = datetime.utcnow()

    def _latest_per_day(rows):
        """Groups rows by day, keeping only the rows of the latest snapshot per day."""
        best: dict = {}
        for r in rows:
            d = r.period_start.date()
            if d not in best or r.period_start > best[d]:
                best[d] = r.period_start
        grouped: dict = {}
        for r in rows:
            if r.period_start == best.get(r.period_start.date()):
                grouped.setdefault(r.period_start.date(), []).append(r)
        return grouped

    def _build_series(labels: list, per_day: dict, key_getter, value_getter, max_keys=8):
        totals: dict = {}
        for rows in per_day.values():
            for r in rows:
                k = key_getter(r)
                totals[k] = totals.get(k, 0) + value_getter(r)
        top = [k for k, _ in sorted(totals.items(), key=lambda item: -item[1])][:max_keys]
        order = {k: i for i, k in enumerate(top)}
        label_dates = [datetime.strptime(d, "%Y-%m-%d").date() for d in labels]
        matrix = [[0] * len(order) for _ in labels]
        for i, d in enumerate(label_dates):
            for r in per_day.get(d, []):
                k = key_getter(r)
                if k in order:
                    matrix[i][order[k]] += value_getter(r)
        return [
            {"name": name, "values": [matrix[i][idx] for i in range(len(labels))]}
            for name, idx in order.items()
        ]

    # --- Content types: last 7 days (latest snapshot per day) ---
    ct_start = now - timedelta(days=7)
    ct_rows = db.query(ContentTypeStat).filter(ContentTypeStat.period_start >= ct_start).all()
    ct_days = sorted({r.period_start.date() for r in ct_rows})
    ct_labels = [d.strftime("%Y-%m-%d") for d in ct_days]
    ct_per_day = _latest_per_day(ct_rows)
    content_types = {
        "available": len(ct_rows) > 0,
        "labels": ct_labels,
        "series": _build_series(ct_labels, ct_per_day, lambda r: r.content_type, lambda r: r.requests, max_keys=6),
        "bytes_series": _build_series(ct_labels, ct_per_day, lambda r: r.content_type, lambda r: r.bytes, max_keys=6),
    }

    # --- Country trend: last 30 days (latest snapshot per day) ---
    co_start = now - timedelta(days=30)
    co_rows = db.query(CountryStat).filter(CountryStat.period_start >= co_start).all()
    co_days = sorted({r.period_start.date() for r in co_rows})
    co_labels = [d.strftime("%Y-%m-%d") for d in co_days]
    co_per_day = _latest_per_day(co_rows)
    country_trend = {
        "available": len(co_rows) > 0,
        "labels": co_labels,
        "series": _build_series(co_labels, co_per_day, lambda r: r.country, lambda r: r.requests, max_keys=8),
    }

    # --- Status trend: last 30 days (latest snapshot per day) ---
    st_rows = db.query(StatusCodeStat).filter(StatusCodeStat.period_start >= co_start).all()
    st_days = sorted({r.period_start.date() for r in st_rows})
    st_labels = [d.strftime("%Y-%m-%d") for d in st_days]
    st_per_day = _latest_per_day(st_rows)
    status_trend = {
        "available": len(st_rows) > 0,
        "labels": st_labels,
        "series": _build_series(st_labels, st_per_day, lambda r: r.status_group, lambda r: r.requests, max_keys=4),
    }

    # --- Top URLs: latest snapshot, top 10 ---
    latest_ts = db.query(func.max(TopUrlStat.period_start)).scalar()
    top_urls = {"available": False, "urls": []}
    if latest_ts:
        url_rows = (
            db.query(TopUrlStat)
            .filter(TopUrlStat.period_start == latest_ts)
            .order_by(desc(TopUrlStat.requests))
            .limit(10)
            .all()
        )
        top_urls = {
            "available": True,
            "urls": [{"path": r.path, "requests": r.requests} for r in url_rows],
        }

    return {
        "content_types": content_types,
        "country_trend": country_trend,
        "status_trend": status_trend,
        "top_urls": top_urls,
    }


@app.get("/api/analytics/summary")
async def analytics_summary(
    _auth: bool = Depends(auth.get_current_session),
    db: Session = Depends(get_db),
):
    since = datetime.utcnow() - timedelta(hours=24)
    raw_rows = db.query(AnalyticsSnapshot).filter(AnalyticsSnapshot.timestamp >= since).all()
    hourly_rows = db.query(AnalyticsHourly).filter(AnalyticsHourly.hour_start >= since).all()

    total_requests = sum(r.requests_total for r in raw_rows) + sum(r.requests_total for r in hourly_rows)
    total_cached = sum(r.requests_cached for r in raw_rows) + sum(r.requests_cached for r in hourly_rows)
    total_bandwidth = sum(r.bandwidth_total_bytes for r in raw_rows) + sum(r.bandwidth_total_bytes for r in hourly_rows)
    total_threats = sum(r.threats_total for r in raw_rows) + sum(r.threats_total for r in hourly_rows)
    cache_ratio = (total_cached / total_requests * 100) if total_requests else 0

    last_updated = None
    if raw_rows:
        last_updated = max(r.timestamp for r in raw_rows).isoformat()
    elif hourly_rows:
        last_updated = max(r.hour_start for r in hourly_rows).isoformat()

    return {
        "requests_24h": total_requests,
        "cache_ratio_pct": round(cache_ratio, 1),
        "bandwidth_24h_mb": round(total_bandwidth / 1_000_000, 2),
        "threats_24h": total_threats,
        "last_updated": last_updated,
    }


@app.get("/api/analytics/insights")
async def analytics_insights(
    _auth: bool = Depends(auth.get_current_session),
    db: Session = Depends(get_db),
):
    """Aggregated insights from existing data (no extra Cloudflare fetches):
    day/week deltas and a 7-day threat briefing."""
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    def _sum_rows(rows) -> dict:
        return {
            "requests": sum(r.requests_total for r in rows),
            "bandwidth_bytes": sum(r.bandwidth_total_bytes for r in rows),
            "threats": sum(r.threats_total for r in rows),
        }

    def _delta(cur: float, prev: float):
        if prev <= 0:
            return None if cur == 0 else 100.0
        return round((cur - prev) / prev * 100, 1)

    # --- Day & week deltas (raw + hourly cover the last 30 days) ---
    day_rows = (
        db.query(AnalyticsSnapshot).filter(AnalyticsSnapshot.timestamp >= today_start).all()
        + db.query(AnalyticsHourly).filter(AnalyticsHourly.hour_start >= today_start).all()
    )
    prev_day_rows = (
        db.query(AnalyticsSnapshot).filter(
            AnalyticsSnapshot.timestamp >= today_start - timedelta(days=1),
            AnalyticsSnapshot.timestamp < today_start,
        ).all()
        + db.query(AnalyticsHourly).filter(
            AnalyticsHourly.hour_start >= today_start - timedelta(days=1),
            AnalyticsHourly.hour_start < today_start,
        ).all()
    )
    week_start = today_start - timedelta(days=7)
    prev_week_start = week_start - timedelta(days=7)
    week_rows = (
        db.query(AnalyticsSnapshot).filter(AnalyticsSnapshot.timestamp >= week_start).all()
        + db.query(AnalyticsHourly).filter(AnalyticsHourly.hour_start >= week_start).all()
    )
    prev_week_rows = (
        db.query(AnalyticsSnapshot).filter(
            AnalyticsSnapshot.timestamp >= prev_week_start,
            AnalyticsSnapshot.timestamp < week_start,
        ).all()
        + db.query(AnalyticsHourly).filter(
            AnalyticsHourly.hour_start >= prev_week_start,
            AnalyticsHourly.hour_start < week_start,
        ).all()
    )

    today = _sum_rows(day_rows)
    yesterday = _sum_rows(prev_day_rows)
    week = _sum_rows(week_rows)
    prev_week = _sum_rows(prev_week_rows)

    # --- Threat briefing (last 7 days from the security feed) ---
    threat_start = now - timedelta(days=7)
    events = db.query(ThreatEvent).filter(ThreatEvent.timestamp >= threat_start).all()
    attacks_today = sum(1 for e in events if e.timestamp >= today_start)
    attacks_yesterday = sum(
        1 for e in events
        if today_start - timedelta(days=1) <= e.timestamp < today_start
    )
    ips = Counter((e.client_ip or "") for e in events)
    uas = Counter((e.user_agent or "") for e in events)
    paths = Counter((e.path or "") for e in events)

    return {
        "day_deltas": {
            "requests": _delta(today["requests"], yesterday["requests"]),
            "bandwidth": _delta(today["bandwidth_bytes"], yesterday["bandwidth_bytes"]),
            "threats": _delta(today["threats"], yesterday["threats"]),
        },
        "week_deltas": {
            "requests": _delta(week["requests"], prev_week["requests"]),
            "threats": _delta(week["threats"], prev_week["threats"]),
        },
        "threat_briefing": {
            "total_7d": len(events),
            "attacks_today": attacks_today,
            "attacks_yesterday": attacks_yesterday,
            "trend_pct": _delta(attacks_today, attacks_yesterday),
            "top_ips": [{"ip": collector.mask_ip(ip), "count": c} for ip, c in ips.most_common(5) if ip],
            "top_uas": [{"ua": ua, "count": c} for ua, c in uas.most_common(5) if ua],
            "top_paths": [{"path": path, "count": c} for path, c in paths.most_common(5) if path],
        },
    }


@app.get("/api/collector/status")
async def collector_status(
    _auth: bool = Depends(auth.get_current_session),
    db: Session = Depends(get_db),
):
    """Last collector run and storage statistics – for diagnostics on the settings page."""
    last_run = db.query(CollectorRun).order_by(desc(CollectorRun.timestamp)).first()
    storage = get_storage_stats(db)
    return {
        "last_run": {
            "timestamp": last_run.timestamp.isoformat() if last_run else None,
            "success": last_run.success if last_run else None,
            "message": last_run.message if last_run else "No run yet",
            "duration_ms": last_run.duration_ms if last_run else None,
            "records_fetched": last_run.records_fetched if last_run else None,
        } if last_run else None,
        "storage": storage,
        "interval_minutes": settings.COLLECTOR_INTERVAL_MINUTES,
        "zone_configured": bool(settings.CLOUDFLARE_API_TOKEN and settings.CLOUDFLARE_ZONE_ID),
    }


@app.get("/api/security/feed")
async def security_feed(request: Request, _auth: bool = Depends(auth.get_current_session), db: Session = Depends(get_db)):
    rows = (
        db.query(ThreatEvent)
        .order_by(desc(ThreatEvent.timestamp))
        .limit(settings.SECURITY_FEED_LIMIT)
        .all()
    )

    # Privacy: IPs are masked if MASK_IPS_IN_FEED is active. Masking can be temporarily
    # disabled on the admin page (only for the active browser session) - this requires
    # a valid admin grant.
    grant = request.headers.get("x-admin-grant", "")
    reveal_ips = (
        request.headers.get("x-reveal-ips", "") == "1"
        and grant
        and auth.verify_admin_token_grant(grant)
    )
    mask_ips = settings.MASK_IPS_IN_FEED and not reveal_ips

    return [
        {
            "timestamp": r.timestamp.isoformat(),
            "client_ip": collector.mask_ip(r.client_ip) if mask_ips else r.client_ip,
            "country": r.country,
            "action": r.action,
            "source": r.source,
            "path": r.path,
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Quick actions API
# ---------------------------------------------------------------------------
class ToggleGeneric(BaseModel):
    enabled: bool


class PurgeUrlsPayload(BaseModel):
    urls: list[str]


def _require_zone_configured():
    if not settings.CLOUDFLARE_API_TOKEN or not settings.CLOUDFLARE_ZONE_ID:
        raise HTTPException(
            status_code=400,
            detail="Cloudflare not configured (set CLOUDFLARE_API_TOKEN / CLOUDFLARE_ZONE_ID in the .env)",
        )


@app.get("/api/zone/status")
async def zone_status(_auth: bool = Depends(auth.get_current_session)):
    dev_mode = await collector.get_zone_setting("development_mode")
    security_level = await collector.get_zone_setting("security_level")
    return {
        "development_mode": dev_mode == "on",
        "under_attack_mode": security_level == "under_attack",
    }


@app.get("/api/zone/verify")
async def zone_verify(_auth: bool = Depends(auth.get_current_session)):
    """Read-only diagnostic: validates the configured token+zone via the same GraphQL
    query the collector uses. Returns a clear, human-readable error message on failure –
    useful for debugging (e.g. 'Zone not found' / 403 / 401)."""
    return await collector.verify_zone_access()


@app.post("/api/zone/dev-mode")
async def toggle_dev_mode(payload: ToggleGeneric, _auth: bool = Depends(auth.get_current_session)):
    if not settings.FEATURE_DEV_MODE_TOGGLE:
        raise HTTPException(status_code=403, detail="Feature disabled")
    _require_zone_configured()
    ok, message = await collector.toggle_development_mode(payload.enabled)
    if not ok:
        raise HTTPException(status_code=502, detail=message)
    return {"success": True}


@app.post("/api/zone/under-attack")
async def toggle_under_attack(payload: ToggleGeneric, _auth: bool = Depends(auth.get_current_session)):
    if not settings.FEATURE_UNDER_ATTACK_TOGGLE:
        raise HTTPException(status_code=403, detail="Feature disabled")
    _require_zone_configured()
    ok, message = await collector.toggle_under_attack_mode(payload.enabled)
    if not ok:
        raise HTTPException(status_code=502, detail=message)
    return {"success": True}


@app.post("/api/zone/purge-cache")
async def purge_cache_endpoint(_auth: bool = Depends(auth.get_current_session)):
    if not settings.FEATURE_PURGE_CACHE:
        raise HTTPException(status_code=403, detail="Feature disabled")
    _require_zone_configured()
    ok, message = await collector.purge_cache(purge_everything=True)
    if not ok:
        raise HTTPException(status_code=502, detail=message)
    return {"success": True}


@app.post("/api/zone/purge-cache-urls")
async def purge_cache_urls_endpoint(payload: PurgeUrlsPayload, _auth: bool = Depends(auth.get_current_session)):
    """Purges the cache only for selected URLs (uncritical action-center action)."""
    if not settings.FEATURE_PURGE_CACHE:
        raise HTTPException(status_code=403, detail="Feature disabled")
    _require_zone_configured()

    urls = [u.strip() for u in payload.urls if u and u.strip()]
    if not urls:
        raise HTTPException(status_code=400, detail="No URLs provided")
    if len(urls) > 30:
        raise HTTPException(status_code=400, detail="Cloudflare allows max. 30 URLs per purge request")

    ok, message = await collector.purge_cache(purge_everything=False, files=urls)
    if not ok:
        raise HTTPException(status_code=502, detail=message)
    return {"success": True}


@app.get("/api/zone/settings-summary")
async def zone_settings_summary(_auth: bool = Depends(auth.get_current_session)):
    """Read-only overview of uncritical zone settings for the action center."""
    if not settings.FEATURE_ACTION_CENTER:
        raise HTTPException(status_code=403, detail="Feature disabled")
    return await collector.get_zone_settings_summary()


@app.post("/api/collector/run-now")
async def collector_run_now(_auth: bool = Depends(auth.get_current_session)):
    """Triggers a collector run manually (incl. passive analytics), e.g. to test the
    Cloudflare credentials. Read-only, no write actions are triggered."""
    await collector.fetch_analytics_and_store()
    if settings.FEATURE_COUNTRY_CHART or settings.FEATURE_STATUS_CHART:
        await collector.fetch_passive_analytics_and_store()
    return {"success": True}


@app.get("/api/health")
async def health():
    return {"status": "ok", "app": settings.APP_NAME}
