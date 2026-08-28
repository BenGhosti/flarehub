"""
FlareHub – database setup (SQLite via SQLAlchemy).

Data model / retention strategy:
- AnalyticsSnapshot: raw data in COLLECTOR_INTERVAL_MINUTES resolution (e.g. every 10 min).
  Compacted into AnalyticsHourly after RAW_RETENTION_HOURS, then deleted.
- AnalyticsHourly: hourly rollups. Compacted into AnalyticsDaily after HOURLY_RETENTION_DAYS,
  then deleted.
- AnalyticsDaily: daily rollups, kept for DATA_RETENTION_DAYS (long-term history,
  very compact: 1 row per day).
This keeps the DB small even after years of operation, without losing the long-term trend.
"""
from datetime import datetime, timedelta

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text, func
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings

engine = create_engine(
    f"sqlite:///{settings.DATABASE_PATH}",
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class AnalyticsSnapshot(Base):
    """Raw data point in COLLECTOR_INTERVAL_MINUTES resolution."""
    __tablename__ = "analytics_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    requests_total = Column(Integer, default=0)
    requests_cached = Column(Integer, default=0)
    requests_uncached = Column(Integer, default=0)
    bandwidth_total_bytes = Column(Integer, default=0)
    bandwidth_cached_bytes = Column(Integer, default=0)
    bandwidth_uncached_bytes = Column(Integer, default=0)
    threats_total = Column(Integer, default=0)
    page_views = Column(Integer, default=0)
    unique_visitors = Column(Integer, default=0)


class AnalyticsHourly(Base):
    """Hourly rollup. unique_visitors is a max-per-hour approximation (no true
    distinct merge possible, since Cloudflare only delivers pre-aggregated uniques)."""
    __tablename__ = "analytics_hourly"

    id = Column(Integer, primary_key=True, index=True)
    hour_start = Column(DateTime, index=True, unique=True)
    requests_total = Column(Integer, default=0)
    requests_cached = Column(Integer, default=0)
    requests_uncached = Column(Integer, default=0)
    bandwidth_total_bytes = Column(Integer, default=0)
    bandwidth_cached_bytes = Column(Integer, default=0)
    bandwidth_uncached_bytes = Column(Integer, default=0)
    threats_total = Column(Integer, default=0)
    page_views = Column(Integer, default=0)
    unique_visitors_max = Column(Integer, default=0)


class AnalyticsDaily(Base):
    """Daily rollup for the long-term history, very compact."""
    __tablename__ = "analytics_daily"

    id = Column(Integer, primary_key=True, index=True)
    day = Column(DateTime, index=True, unique=True)  # 00:00 UTC des Tages
    requests_total = Column(Integer, default=0)
    requests_cached = Column(Integer, default=0)
    requests_uncached = Column(Integer, default=0)
    bandwidth_total_bytes = Column(Integer, default=0)
    bandwidth_cached_bytes = Column(Integer, default=0)
    bandwidth_uncached_bytes = Column(Integer, default=0)
    threats_total = Column(Integer, default=0)
    page_views = Column(Integer, default=0)
    unique_visitors_max = Column(Integer, default=0)


class ThreatEvent(Base):
    """Single blocked request (WAF / firewall) for the security feed."""
    __tablename__ = "threat_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    client_ip = Column(String, nullable=True)
    country = Column(String, nullable=True)
    action = Column(String, nullable=True)  # block, challenge, jschallenge, ...
    source = Column(String, nullable=True)  # waf, firewall_rule, rate_limit, ...
    path = Column(String, nullable=True)
    user_agent = Column(Text, nullable=True)


class ZoneSettingState(Base):
    """Last known state of zone settings, to cache UI state."""
    __tablename__ = "zone_setting_state"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, index=True)  # z.B. "development_mode", "security_level"
    value = Column(String)
    updated_at = Column(DateTime, default=datetime.utcnow)


class WebAuthnCredential(Base):
    """Registered passkeys/YubiKeys."""
    __tablename__ = "webauthn_credentials"

    id = Column(Integer, primary_key=True, index=True)
    credential_id = Column(String, unique=True, index=True)
    public_key = Column(Text)
    sign_count = Column(Integer, default=0)
    transports = Column(String, nullable=True)
    nickname = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)


class LoginAttempt(Base):
    """For rate limiting and PIN lockout."""
    __tablename__ = "login_attempts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    method = Column(String)  # pin, passkey
    success = Column(Boolean, default=False)
    ip_address = Column(String, nullable=True)


class CollectorRun(Base):
    """Log of collector runs, for diagnostics in the UI (last run, errors, duration)."""
    __tablename__ = "collector_runs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    success = Column(Boolean, default=True)
    message = Column(Text, nullable=True)
    duration_ms = Column(Integer, default=0)
    records_fetched = Column(Integer, default=0)


class CountryStat(Base):
    """Passive analytics: requests per origin country for a collection interval (last 24h)."""
    __tablename__ = "country_stats"

    id = Column(Integer, primary_key=True, index=True)
    period_start = Column(DateTime, index=True)  # Beginn des Sammelintervalls
    country = Column(String, index=True)
    requests = Column(Integer, default=0)


class StatusCodeStat(Base):
    """Passive analytics: requests per status code group (2xx/3xx/4xx/5xx) per interval."""
    __tablename__ = "status_code_stats"

    id = Column(Integer, primary_key=True, index=True)
    period_start = Column(DateTime, index=True)
    status_group = Column(String, index=True)  # "2xx", "3xx", "4xx", "5xx"
    requests = Column(Integer, default=0)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _hour_floor(dt: datetime) -> datetime:
    return dt.replace(minute=0, second=0, microsecond=0)


def _day_floor(dt: datetime) -> datetime:
    return dt.replace(hour=0, minute=0, second=0, microsecond=0)


def rollup_raw_to_hourly(db, older_than_hours: int):
    """Compacts AnalyticsSnapshot rows older than older_than_hours into AnalyticsHourly
    and deletes the compacted raw data afterwards."""
    cutoff = datetime.utcnow() - timedelta(hours=older_than_hours)
    rows = (
        db.query(AnalyticsSnapshot)
        .filter(AnalyticsSnapshot.timestamp < cutoff)
        .order_by(AnalyticsSnapshot.timestamp.asc())
        .all()
    )
    if not rows:
        return 0

    buckets: dict[datetime, dict] = {}
    for r in rows:
        hour = _hour_floor(r.timestamp)
        b = buckets.setdefault(hour, {
            "requests_total": 0, "requests_cached": 0, "requests_uncached": 0,
            "bandwidth_total_bytes": 0, "bandwidth_cached_bytes": 0, "bandwidth_uncached_bytes": 0,
            "threats_total": 0, "page_views": 0, "unique_visitors_max": 0,
        })
        b["requests_total"] += r.requests_total
        b["requests_cached"] += r.requests_cached
        b["requests_uncached"] += r.requests_uncached
        b["bandwidth_total_bytes"] += r.bandwidth_total_bytes
        b["bandwidth_cached_bytes"] += r.bandwidth_cached_bytes
        b["bandwidth_uncached_bytes"] += r.bandwidth_uncached_bytes
        b["threats_total"] += r.threats_total
        b["page_views"] += r.page_views
        b["unique_visitors_max"] = max(b["unique_visitors_max"], r.unique_visitors)

    for hour, agg in buckets.items():
        existing = db.query(AnalyticsHourly).filter_by(hour_start=hour).first()
        if existing:
            existing.requests_total += agg["requests_total"]
            existing.requests_cached += agg["requests_cached"]
            existing.requests_uncached += agg["requests_uncached"]
            existing.bandwidth_total_bytes += agg["bandwidth_total_bytes"]
            existing.bandwidth_cached_bytes += agg["bandwidth_cached_bytes"]
            existing.bandwidth_uncached_bytes += agg["bandwidth_uncached_bytes"]
            existing.threats_total += agg["threats_total"]
            existing.page_views += agg["page_views"]
            existing.unique_visitors_max = max(existing.unique_visitors_max, agg["unique_visitors_max"])
        else:
            db.add(AnalyticsHourly(hour_start=hour, **agg))

    ids = [r.id for r in rows]
    db.query(AnalyticsSnapshot).filter(AnalyticsSnapshot.id.in_(ids)).delete(synchronize_session=False)
    db.commit()
    return len(rows)


def rollup_hourly_to_daily(db, older_than_days: int):
    """Compacts AnalyticsHourly rows older than older_than_days into AnalyticsDaily
    and deletes the compacted hourly rollups afterwards."""
    cutoff = datetime.utcnow() - timedelta(days=older_than_days)
    rows = (
        db.query(AnalyticsHourly)
        .filter(AnalyticsHourly.hour_start < cutoff)
        .order_by(AnalyticsHourly.hour_start.asc())
        .all()
    )
    if not rows:
        return 0

    buckets: dict[datetime, dict] = {}
    for r in rows:
        day = _day_floor(r.hour_start)
        b = buckets.setdefault(day, {
            "requests_total": 0, "requests_cached": 0, "requests_uncached": 0,
            "bandwidth_total_bytes": 0, "bandwidth_cached_bytes": 0, "bandwidth_uncached_bytes": 0,
            "threats_total": 0, "page_views": 0, "unique_visitors_max": 0,
        })
        b["requests_total"] += r.requests_total
        b["requests_cached"] += r.requests_cached
        b["requests_uncached"] += r.requests_uncached
        b["bandwidth_total_bytes"] += r.bandwidth_total_bytes
        b["bandwidth_cached_bytes"] += r.bandwidth_cached_bytes
        b["bandwidth_uncached_bytes"] += r.bandwidth_uncached_bytes
        b["threats_total"] += r.threats_total
        b["page_views"] += r.page_views
        b["unique_visitors_max"] = max(b["unique_visitors_max"], r.unique_visitors_max)

    for day, agg in buckets.items():
        existing = db.query(AnalyticsDaily).filter_by(day=day).first()
        if existing:
            existing.requests_total += agg["requests_total"]
            existing.requests_cached += agg["requests_cached"]
            existing.requests_uncached += agg["requests_uncached"]
            existing.bandwidth_total_bytes += agg["bandwidth_total_bytes"]
            existing.bandwidth_cached_bytes += agg["bandwidth_cached_bytes"]
            existing.bandwidth_uncached_bytes += agg["bandwidth_uncached_bytes"]
            existing.threats_total += agg["threats_total"]
            existing.page_views += agg["page_views"]
            existing.unique_visitors_max = max(existing.unique_visitors_max, agg["unique_visitors_max"])
        else:
            db.add(AnalyticsDaily(day=day, **agg))

    ids = [r.id for r in rows]
    db.query(AnalyticsHourly).filter(AnalyticsHourly.id.in_(ids)).delete(synchronize_session=False)
    db.commit()
    return len(rows)


def cleanup_old_data(db):
    """Runs the complete retention pipeline: raw -> hourly -> daily,
    and deletes very old daily rollups as well as expired threat events/login attempts."""
    rollup_raw_to_hourly(db, settings.RAW_RETENTION_HOURS)
    rollup_hourly_to_daily(db, settings.HOURLY_RETENTION_DAYS)

    daily_cutoff = datetime.utcnow() - timedelta(days=settings.DATA_RETENTION_DAYS)
    db.query(AnalyticsDaily).filter(AnalyticsDaily.day < daily_cutoff).delete()

    threat_cutoff = datetime.utcnow() - timedelta(days=settings.THREAT_EVENT_RETENTION_DAYS)
    db.query(ThreatEvent).filter(ThreatEvent.timestamp < threat_cutoff).delete()

    passive_cutoff = datetime.utcnow() - timedelta(days=settings.PASSIVE_RETENTION_DAYS)
    db.query(CountryStat).filter(CountryStat.period_start < passive_cutoff).delete()
    db.query(StatusCodeStat).filter(StatusCodeStat.period_start < passive_cutoff).delete()

    login_cutoff = datetime.utcnow() - timedelta(days=7)
    db.query(LoginAttempt).filter(LoginAttempt.timestamp < login_cutoff).delete()

    collector_run_cutoff = datetime.utcnow() - timedelta(days=14)
    db.query(CollectorRun).filter(CollectorRun.timestamp < collector_run_cutoff).delete()

    db.commit()


def db_maintenance() -> dict:
    """Runs SQLite maintenance (VACUUM + ANALYZE) and returns the results.
    VACUUM compacts the file, ANALYZE updates query statistics."""
    import time as _time

    results = {}
    start = _time.monotonic()
    try:
        with engine.connect() as conn:
            conn.exec_driver_sql("VACUUM")
        results["vacuum"] = "OK"
    except Exception as e:
        results["vacuum"] = f"Fehler: {e}"

    try:
        with engine.connect() as conn:
            conn.exec_driver_sql("ANALYZE")
        results["analyze"] = "OK"
    except Exception as e:
        results["analyze"] = f"Fehler: {e}"

    results["duration_ms"] = int((_time.monotonic() - start) * 1000)
    return results


def get_storage_stats(db) -> dict:
    """Row counts per table for display in the UI (settings/admin page)."""
    return {
        "raw_snapshots": db.query(func.count(AnalyticsSnapshot.id)).scalar() or 0,
        "hourly_rollups": db.query(func.count(AnalyticsHourly.id)).scalar() or 0,
        "daily_rollups": db.query(func.count(AnalyticsDaily.id)).scalar() or 0,
        "threat_events": db.query(func.count(ThreatEvent.id)).scalar() or 0,
        "country_stats": db.query(func.count(CountryStat.id)).scalar() or 0,
        "status_code_stats": db.query(func.count(StatusCodeStat.id)).scalar() or 0,
        "collector_runs": db.query(func.count(CollectorRun.id)).scalar() or 0,
    }
