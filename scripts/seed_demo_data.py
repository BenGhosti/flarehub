"""
FlareHub – demo data seed for the test environment (test-webserver.bat).

Creates realistic sample data so the dashboard preview shows populated charts and
a security feed without real Cloudflare credentials.
The data layout matches the production retention strategy exactly:
- Snapshots (10-min resolution) for the last 48 hours  -> 6h/24h view
- Hourly rollups from 48h to 30 days back             -> 7d/30d view
- Daily rollups from 30 to 365 days back              -> 90d/1y view

Usage: DATABASE_PATH is read from the environment (set by the batch file).
"""
import os
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

DB_PATH = os.environ.get("DATABASE_PATH", os.path.join("data", "test.db"))

# IMPORTANT: DATABASE_PATH MUST be set before importing app.database,
# because app.config reads the settings from the environment at module import time.
os.environ["DATABASE_PATH"] = DB_PATH
Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

# Add the project root to sys.path so that "app" is importable,
# regardless of the directory the script is started from.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database import (  # noqa: E402
    init_db, SessionLocal,
    AnalyticsSnapshot, AnalyticsHourly, AnalyticsDaily, ThreatEvent,
    CountryStat, StatusCodeStat, ContentTypeStat, TopUrlStat,
)

random.seed(42)

COUNTRY_POOL = ["DE", "US", "CN", "RU", "BR", "IN", "UA", "NL", "GB", "FR"]
SOURCE_POOL = ["waf", "rate_limit", "firewall_rule", "managed_challenge"]
ACTION_POOL = ["block", "challenge", "jschallenge"]
PATH_POOL = [
    "/wp-login.php", "/xmlrpc.php", "/wp-admin/", "/admin/", "/.env",
    "/phpmyadmin/", "/login", "/api/v1/", "/cgi-bin/", "/config.php",
]
UA_POOL = [
    "curl/8.4.0", "python-requests/2.31", "Go-http-client/1.1",
    "Mozilla/5.0 (compatible; bingbot/2.0)", "sqlmap/1.7", "masscan/1.3",
]


def hour_factor(dt: datetime) -> float:
    """Time-of-day factor: more traffic in the morning/noon/evening, little at night."""
    h = dt.hour
    if 8 <= h < 12:
        return 1.3
    if 12 <= h < 18:
        return 1.5
    if 18 <= h < 23:
        return 1.1
    return 0.4


def random_threats() -> int:
    r = random.random()
    if r < 0.08:
        return random.randint(20, 180)
    if r < 0.45:
        return random.randint(1, 6)
    return 0


def random_ip() -> str:
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def main():
    init_db()
    db = SessionLocal()
    try:
        db.query(AnalyticsSnapshot).delete()
        db.query(AnalyticsHourly).delete()
        db.query(AnalyticsDaily).delete()
        db.query(ThreatEvent).delete()
        db.query(CountryStat).delete()
        db.query(StatusCodeStat).delete()
        db.query(ContentTypeStat).delete()
        db.query(TopUrlStat).delete()
        db.commit()

        now = datetime.utcnow().replace(second=0, microsecond=0)

        # --- Snapshots: last 48 hours, 10-minute resolution ---
        t = now - timedelta(hours=48)
        while t <= now:
            reqs = max(200, int(8000 * hour_factor(t) + random.randint(-800, 800)))
            cached = int(reqs * random.uniform(0.62, 0.78))
            bw_total = reqs * random.randint(1200, 2600)
            db.add(AnalyticsSnapshot(
                timestamp=t,
                requests_total=reqs,
                requests_cached=cached,
                requests_uncached=reqs - cached,
                bandwidth_total_bytes=bw_total,
                bandwidth_cached_bytes=int(bw_total * random.uniform(0.62, 0.78)),
                bandwidth_uncached_bytes=int(bw_total * random.uniform(0.22, 0.38)),
                threats_total=random_threats(),
                page_views=int(reqs * random.uniform(0.55, 0.75)),
                unique_visitors=int(reqs * random.uniform(0.08, 0.2)),
            ))
            t += timedelta(minutes=10)
        db.commit()

        # --- Hourly rollups: 48h to 30 days back ---
        t = now - timedelta(days=30)
        while t < now - timedelta(hours=48):
            reqs = max(200, int(12000 * hour_factor(t) + random.randint(-2000, 2000)))
            cached = int(reqs * random.uniform(0.62, 0.78))
            bw_total = reqs * random.randint(1400, 2800)
            db.add(AnalyticsHourly(
                hour_start=t.replace(minute=0, second=0, microsecond=0),
                requests_total=reqs,
                requests_cached=cached,
                requests_uncached=reqs - cached,
                bandwidth_total_bytes=bw_total,
                bandwidth_cached_bytes=int(bw_total * random.uniform(0.62, 0.78)),
                bandwidth_uncached_bytes=int(bw_total * random.uniform(0.22, 0.38)),
                threats_total=random_threats(),
                page_views=int(reqs * random.uniform(0.55, 0.75)),
                unique_visitors_max=int(reqs * random.uniform(0.08, 0.2)),
            ))
            t += timedelta(hours=1)
        db.commit()

        # --- Daily rollups: 30 to 365 days back ---
        t = now - timedelta(days=365)
        while t < now - timedelta(days=30):
            reqs = max(5000, int(180000 * random.uniform(0.6, 1.3)))
            cached = int(reqs * random.uniform(0.62, 0.78))
            bw_total = reqs * 2000
            db.add(AnalyticsDaily(
                day=t.replace(hour=0, minute=0, second=0, microsecond=0),
                requests_total=reqs,
                requests_cached=cached,
                requests_uncached=reqs - cached,
                bandwidth_total_bytes=bw_total,
                bandwidth_cached_bytes=int(bw_total * random.uniform(0.62, 0.78)),
                bandwidth_uncached_bytes=int(bw_total * random.uniform(0.22, 0.38)),
                threats_total=random.randint(20, 400),
                page_views=int(reqs * 0.65),
                unique_visitors_max=int(reqs * 0.15),
            ))
            t += timedelta(days=1)
        db.commit()

        # --- Security feed: 50 threat events in the last 48h ---
        for _ in range(50):
            db.add(ThreatEvent(
                timestamp=now - timedelta(minutes=random.randint(10, 2880)),
                client_ip=random_ip(),
                country=random.choice(COUNTRY_POOL),
                action=random.choice(ACTION_POOL),
                source=random.choice(SOURCE_POOL),
                path=random.choice(PATH_POOL),
                user_agent=random.choice(UA_POOL),
            ))
        db.commit()

        # --- Passive analytics: daily snapshots for the last 30 days ---
        # (countries, status groups, content types per day; top URLs for today)
        country_weights = {
            "DE": 42, "US": 18, "NL": 9, "FR": 7, "GB": 6, "CN": 5,
            "RU": 4, "BR": 3, "IN": 3, "UA": 2, "JP": 1,
        }
        total_weight = sum(country_weights.values())
        status_dist = {"2xx": 0.74, "3xx": 0.12, "4xx": 0.10, "5xx": 0.04}
        content_dist = {"html": 0.45, "js": 0.16, "image": 0.19, "css": 0.11, "video": 0.05, "other": 0.04}

        for i in range(30):
            day_ts = now - timedelta(days=i, hours=3)  # late evening of that day
            total_reqs = int(1_100_000 * random.uniform(0.6, 1.3))
            for country, weight in country_weights.items():
                db.add(CountryStat(
                    period_start=day_ts,
                    country=country,
                    requests=int(total_reqs * weight / total_weight),
                ))
            for group, share in status_dist.items():
                db.add(StatusCodeStat(
                    period_start=day_ts,
                    status_group=group,
                    requests=int(total_reqs * share),
                ))
            for name, share in content_dist.items():
                db.add(ContentTypeStat(
                    period_start=day_ts,
                    content_type=name,
                    requests=int(total_reqs * share),
                    bytes=int(total_reqs * share * random.randint(900, 4800)),
                ))
        db.commit()

        top_urls = [
            "/", "/favicon.ico", "/assets/app.js", "/api/v1/", "/wp-login.php",
            "/robots.txt", "/.env.backup", "/admin/", "/assets/style.css", "/images/logo.png",
        ]
        for path in top_urls:
            db.add(TopUrlStat(
                period_start=now,
                path=path,
                requests=random.randint(60, 2200),
            ))
        db.commit()

        counts = (
            db.query(AnalyticsSnapshot).count(),
            db.query(AnalyticsHourly).count(),
            db.query(AnalyticsDaily).count(),
            db.query(ThreatEvent).count(),
            db.query(CountryStat).count(),
            db.query(StatusCodeStat).count(),
            db.query(ContentTypeStat).count(),
            db.query(TopUrlStat).count(),
        )
        print(
            f"Demo data written to {DB_PATH}\n"
            f"  Snapshots: {counts[0]} | Hourly rollups: {counts[1]} | "
            f"Daily rollups: {counts[2]} | Security events: {counts[3]} | "
            f"Countries: {counts[4]} | Status codes: {counts[5]} | "
            f"Content types: {counts[6]} | Top URLs: {counts[7]}"
        )
    finally:
        db.close()


if __name__ == "__main__":
    main()
