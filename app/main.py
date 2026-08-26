"""
FlareHub – Cloudflare Analytics & Quick Actions Dashboard.
FastAPI-Backend mit Jinja2-Templates, WebAuthn/PIN-Auth und Cloudflare GraphQL-Analytics.
"""
import logging
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse

from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.config import settings
from app.database import (
    init_db, get_db, SessionLocal,
    AnalyticsSnapshot, AnalyticsHourly, AnalyticsDaily, ThreatEvent, LoginAttempt, CollectorRun,
    WebAuthnCredential, get_storage_stats,
)
from app import auth
from app import collector

logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL, logging.INFO))
logger = logging.getLogger("flarehub")

app = FastAPI(title=settings.APP_NAME)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

scheduler = AsyncIOScheduler()

# Simple in-memory rate limiter für Login-Endpunkte
_rate_limit_buckets: dict = {}


@app.middleware("http")
async def csrf_origin_check(request: Request, call_next):
    """Leichtgewichtiger CSRF-Schutz für zustandsverändernde Requests.

    Bei POST/PUT/PATCH/DELETE wird geprüft, dass ein gesendeter Origin-Header zum
    Host-Header passt (Same-Origin). Requests ohne Origin-Header (curl, Server-to-Server)
    bleiben erlaubt. Zusammen mit dem SameSite=Lax-Cookie verhindert das Cross-Site-
    Requests gegen Quick Actions / Passkey-Verwaltung."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = request.headers.get("origin")
        if origin:
            host = request.headers.get("host", "")
            try:
                origin_host = urlparse(origin).netloc
            except ValueError:
                origin_host = ""
            if origin_host and origin_host != host:
                return JSONResponse(status_code=403, content={"detail": "Cross-Origin Request abgelehnt"})
    return await call_next(request)


@app.middleware("http")
async def no_store_cache(request: Request, call_next):
    """Verhindert Browser-Caching von authentifiziertem Inhalt (Seiten + APIs).

    /static-Assets duerfen gecacht werden, alles andere bekommt Cache-Control: no-store.
    Abschaltbar ueber HTTP_CACHE_NO_STORE=false in der .env."""
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


@app.on_event("startup")
async def on_startup():
    init_db()
    if not settings.auth_disabled:
        logger.info(f"Auth-Modus: {settings.AUTH_MODE}")
    else:
        logger.warning("AUTH_MODE=none – Dashboard ist UNGESCHÜTZT erreichbar!")

    if settings.SESSION_SECRET_KEY == "change-me-to-a-long-random-string":
        logger.warning("SESSION_SECRET_KEY ist noch der Default-Wert – bitte in der .env auf einen zufälligen String setzen!")

    scheduler.add_job(
        collector.fetch_analytics_and_store,
        "interval",
        minutes=settings.COLLECTOR_INTERVAL_MINUTES,
        id="analytics_collector",
        next_run_time=datetime.now() if settings.COLLECTOR_RUN_ON_STARTUP else None,
    )
    scheduler.start()
    logger.info(f"{settings.APP_NAME} gestartet – Collector-Intervall: {settings.COLLECTOR_INTERVAL_MINUTES}min")


@app.on_event("shutdown")
async def on_shutdown():
    scheduler.shutdown()


# ---------------------------------------------------------------------------
# Auth Endpoints
# ---------------------------------------------------------------------------
class PinPayload(BaseModel):
    pin: str
    remember_me: bool = False


class PasskeyVerifyPayload(BaseModel):
    credential: dict
    remember_me: bool = False


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
        token = request.cookies.get(settings.SESSION_COOKIE_NAME)
        if token:
            authenticated = auth.verify_session_token(token)

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
        raise HTTPException(status_code=429, detail="Zu viele Anfragen. Bitte kurz warten.")

    ok, message = auth.verify_pin(payload.pin, client_ip)

    db = SessionLocal()
    try:
        db.add(LoginAttempt(method="pin", success=ok, ip_address=client_ip))
        db.commit()
    finally:
        db.close()

    if not ok:
        raise HTTPException(status_code=401, detail=message)

    response = JSONResponse({"success": True})
    auth.set_session_cookie(response, remember_me=payload.remember_me)
    return response


@app.post("/api/passkey/auth-options")
async def passkey_auth_options(db: Session = Depends(get_db)):
    if not settings.auth_passkey_enabled:
        raise HTTPException(status_code=403, detail="Passkey-Login ist deaktiviert")
    options_json = auth.build_authentication_options(db)
    return JSONResponse(content=options_json, media_type="application/json")


@app.post("/api/passkey/auth-verify")
async def passkey_auth_verify(payload: PasskeyVerifyPayload, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    if not _rate_limit_ok(client_ip):
        raise HTTPException(status_code=429, detail="Zu viele Anfragen. Bitte kurz warten.")

    ok, message = auth.verify_passkey_authentication(db, payload.credential)

    db.add(LoginAttempt(method="passkey", success=ok, ip_address=client_ip))
    db.commit()

    if not ok:
        raise HTTPException(status_code=401, detail=message)

    response = JSONResponse({"success": True})
    auth.set_session_cookie(response, remember_me=payload.remember_me)
    return response


def require_admin_grant(request: Request) -> bool:
    """Dependency: verlangt zusätzlich zur normalen Session ein gültiges Admin-Token-Grant.
    Schützt die Passkey-Verwaltung (Hinzufügen/Löschen) getrennt vom normalen Login."""
    auth.get_current_session(request)
    grant = request.cookies.get("flarehub_admin_grant")
    if not grant or not auth.verify_admin_token_grant(grant):
        raise HTTPException(status_code=403, detail="Admin-Token erforderlich")
    return True


@app.post("/api/admin/verify")
async def admin_verify(payload: AdminTokenPayload, request: Request):
    """Prüft das Admin-Token aus der .env und stellt bei Erfolg ein kurzlebiges Grant-Cookie aus."""
    auth.get_current_session(request)
    client_ip = request.client.host if request.client else "unknown"
    if not _rate_limit_ok(client_ip):
        raise HTTPException(status_code=429, detail="Zu viele Anfragen. Bitte kurz warten.")

    ok, message = auth.verify_admin_token(payload.token, client_ip)
    if not ok:
        raise HTTPException(status_code=401, detail=message)

    response = JSONResponse({"success": True})
    # Admin-Grant bewusst als Browser-Session-Cookie (kein max_age -> nichts wird
    # auf der Platte gecacht). Die Gültigkeit ist ohnehin durch das signierte
    # Token auf 10 Minuten begrenzt.
    response.set_cookie(
        key="flarehub_admin_grant",
        value=auth.create_admin_token_grant(),
        httponly=True,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite=settings.SESSION_COOKIE_SAMESITE,
    )
    return response


@app.get("/api/admin/status")
async def admin_status(request: Request):
    auth.get_current_session(request)
    grant = request.cookies.get("flarehub_admin_grant")
    unlocked = bool(grant and auth.verify_admin_token_grant(grant))
    return {"admin_unlocked": unlocked}


@app.post("/api/passkey/register-options")
async def passkey_register_options(_admin: bool = Depends(require_admin_grant), db: Session = Depends(get_db)):
    """Geschützt durch Session + Admin-Token-Grant. Startet die Registrierung eines neuen Passkeys."""
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
    response = JSONResponse({"success": True})
    response.delete_cookie(settings.SESSION_COOKIE_NAME)
    response.delete_cookie("flarehub_admin_grant")
    return response


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if settings.auth_disabled:
        return RedirectResponse(url="/")
    return templates.TemplateResponse("login.html", {
        "request": request,
        "app_name": settings.APP_NAME,
        "auth_mode": settings.AUTH_MODE,
        "pin_length": settings.AUTH_PIN_LENGTH,
        "default_theme": settings.DEFAULT_THEME,
    })


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    if not settings.auth_disabled:
        token = request.cookies.get(settings.SESSION_COOKIE_NAME)
        if not token or not auth.verify_session_token(token):
            return RedirectResponse(url="/login")

    return templates.TemplateResponse("settings.html", {
        "request": request,
        "app_name": settings.APP_NAME,
        "default_theme": settings.DEFAULT_THEME,
        "admin_token_configured": bool(settings.ADMIN_TOKEN),
    })


@app.get("/", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    if not settings.auth_disabled:
        token = request.cookies.get(settings.SESSION_COOKIE_NAME)
        if not token or not auth.verify_session_token(token):
            return RedirectResponse(url="/login")

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "app_name": settings.APP_NAME,
        "default_theme": settings.DEFAULT_THEME,
        "feature_requests_chart": settings.FEATURE_REQUESTS_CHART,
        "feature_bandwidth_chart": settings.FEATURE_BANDWIDTH_CHART,
        "feature_cache_ratio_chart": settings.FEATURE_CACHE_RATIO_CHART,
        "feature_threats_chart": settings.FEATURE_THREATS_CHART,
        "feature_security_feed": settings.FEATURE_SECURITY_FEED,
        "feature_quick_actions": settings.FEATURE_QUICK_ACTIONS,
        "feature_dev_mode_toggle": settings.FEATURE_DEV_MODE_TOGGLE,
        "feature_purge_cache": settings.FEATURE_PURGE_CACHE,
        "feature_under_attack_toggle": settings.FEATURE_UNDER_ATTACK_TOGGLE,
        "auto_refresh_seconds": settings.DASHBOARD_AUTO_REFRESH_SECONDS,
        "zone_configured": bool(settings.CLOUDFLARE_API_TOKEN and settings.CLOUDFLARE_ZONE_ID),
    })


# ---------------------------------------------------------------------------
# Analytics Data API
# ---------------------------------------------------------------------------
@app.get("/api/analytics/timeseries")
async def analytics_timeseries(
    range: str = "24h",
    _auth: bool = Depends(auth.get_current_session),
    db: Session = Depends(get_db),
):
    """Liefert Zeitreihendaten für den gewählten Zeitraum. Wählt automatisch die passende
    Auflösung: kurze Zeiträume nutzen Rohdaten (10-Min-Auflösung), lange nutzen die
    Stunden- bzw. Tages-Rollups, damit die Antwort klein bleibt und alte Daten trotz
    Verdichtung weiterhin sichtbar sind."""
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
    bw_total, bw_cached, threats, uniques = [], [], [], []

    if resolution == "raw":
        # Rohdaten liegen nur für die letzten RAW_RETENTION_HOURS vor; ältere Punkte im
        # gewählten Fenster kommen zusätzlich aus den Stunden-Rollups, damit z.B. bei
        # 24h-Ansicht kurz nach dem Verdichtungslauf keine Lücke entsteht.
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
        for r in raw_rows:
            labels.append(r.timestamp.strftime("%Y-%m-%d %H:%M"))
            req_total.append(r.requests_total)
            req_cached.append(r.requests_cached)
            req_uncached.append(r.requests_uncached)
            bw_total.append(round(r.bandwidth_total_bytes / 1_000_000, 2))
            bw_cached.append(round(r.bandwidth_cached_bytes / 1_000_000, 2))
            threats.append(r.threats_total)
            uniques.append(r.unique_visitors)

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


@app.get("/api/collector/status")
async def collector_status(
    _auth: bool = Depends(auth.get_current_session),
    db: Session = Depends(get_db),
):
    """Letzter Collector-Lauf und Speicherstatistik – für Diagnose auf der Einstellungsseite."""
    last_run = db.query(CollectorRun).order_by(desc(CollectorRun.timestamp)).first()
    storage = get_storage_stats(db)
    return {
        "last_run": {
            "timestamp": last_run.timestamp.isoformat() if last_run else None,
            "success": last_run.success if last_run else None,
            "message": last_run.message if last_run else "Noch kein Lauf erfolgt",
            "duration_ms": last_run.duration_ms if last_run else None,
            "records_fetched": last_run.records_fetched if last_run else None,
        } if last_run else None,
        "storage": storage,
        "interval_minutes": settings.COLLECTOR_INTERVAL_MINUTES,
        "zone_configured": bool(settings.CLOUDFLARE_API_TOKEN and settings.CLOUDFLARE_ZONE_ID),
    }


@app.get("/api/security/feed")
async def security_feed(
    _auth: bool = Depends(auth.get_current_session),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(ThreatEvent)
        .order_by(desc(ThreatEvent.timestamp))
        .limit(settings.SECURITY_FEED_LIMIT)
        .all()
    )
    return [
        {
            "timestamp": r.timestamp.isoformat(),
            "client_ip": r.client_ip,
            "country": r.country,
            "action": r.action,
            "source": r.source,
            "path": r.path,
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Quick Actions API
# ---------------------------------------------------------------------------
class ToggleGeneric(BaseModel):
    enabled: bool


def _require_zone_configured():
    if not settings.CLOUDFLARE_API_TOKEN or not settings.CLOUDFLARE_ZONE_ID:
        raise HTTPException(
            status_code=400,
            detail="Cloudflare nicht konfiguriert (CLOUDFLARE_API_TOKEN / CLOUDFLARE_ZONE_ID in der .env setzen)",
        )


@app.get("/api/zone/status")
async def zone_status(_auth: bool = Depends(auth.get_current_session)):
    dev_mode = await collector.get_zone_setting("development_mode")
    security_level = await collector.get_zone_setting("security_level")
    return {
        "development_mode": dev_mode == "on",
        "under_attack_mode": security_level == "under_attack",
    }


@app.post("/api/zone/dev-mode")
async def toggle_dev_mode(payload: ToggleGeneric, _auth: bool = Depends(auth.get_current_session)):
    if not settings.FEATURE_DEV_MODE_TOGGLE:
        raise HTTPException(status_code=403, detail="Feature deaktiviert")
    _require_zone_configured()
    ok, message = await collector.toggle_development_mode(payload.enabled)
    if not ok:
        raise HTTPException(status_code=502, detail=message)
    return {"success": True}


@app.post("/api/zone/under-attack")
async def toggle_under_attack(payload: ToggleGeneric, _auth: bool = Depends(auth.get_current_session)):
    if not settings.FEATURE_UNDER_ATTACK_TOGGLE:
        raise HTTPException(status_code=403, detail="Feature deaktiviert")
    _require_zone_configured()
    ok, message = await collector.toggle_under_attack_mode(payload.enabled)
    if not ok:
        raise HTTPException(status_code=502, detail=message)
    return {"success": True}


@app.post("/api/zone/purge-cache")
async def purge_cache_endpoint(_auth: bool = Depends(auth.get_current_session)):
    if not settings.FEATURE_PURGE_CACHE:
        raise HTTPException(status_code=403, detail="Feature deaktiviert")
    _require_zone_configured()
    ok, message = await collector.purge_cache(purge_everything=True)
    if not ok:
        raise HTTPException(status_code=502, detail=message)
    return {"success": True}


@app.post("/api/collector/run-now")
async def collector_run_now(_auth: bool = Depends(auth.get_current_session)):
    """Löst manuell einen Collector-Lauf aus, z.B. zum Testen der Cloudflare-Zugangsdaten."""
    await collector.fetch_analytics_and_store()
    return {"success": True}


@app.get("/api/health")
async def health():
    return {"status": "ok", "app": settings.APP_NAME}
