"""
FlareHub – Demo-Datenseed für die Testumgebung (test-webserver.bat).

Erzeugt realistische Beispieldaten, damit das Dashboard in der Vorschau
gefüllte Charts und einen Security-Feed zeigt, ohne echte Cloudflare-Zugangsdaten.
Die Datenaufteilung entspricht exakt der Produktions-Aufbewahrungsstrategie:
- Snapshots (10-Min-Auflösung) für die letzten 48 Stunden  -> 6h/24h-Ansicht
- Stunden-Rollups von 48h bis 30 Tage zurück               -> 7T/30T-Ansicht
- Tages-Rollups von 30 bis 365 Tage zurück                 -> 90T/1J-Ansicht

Nutzung: DATABASE_PATH wird aus der Umgebung gelesen (setzt die Batch-Datei).
"""
import os
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

DB_PATH = os.environ.get("DATABASE_PATH", os.path.join("data", "test.db"))

# WICHTIG: DATABASE_PATH MUSS vor dem Import von app.database gesetzt sein,
# weil app.config die Einstellungen beim Modulimport aus der Umgebung liest.
os.environ["DATABASE_PATH"] = DB_PATH
Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

# Projekt-Root auf den sys.path, damit "app" importierbar ist,
# egal aus welchem Verzeichnis das Skript gestartet wird.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database import (  # noqa: E402
    init_db, SessionLocal,
    AnalyticsSnapshot, AnalyticsHourly, AnalyticsDaily, ThreatEvent,
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
    """Tageszeit-Faktor: morgens/mittags/abends mehr Traffic, nachts wenig."""
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
        db.commit()

        now = datetime.utcnow().replace(second=0, microsecond=0)

        # --- Snapshots: letzte 48 Stunden, 10-Minuten-Auflösung ---
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

        # --- Stunden-Rollups: 48h bis 30 Tage zurück ---
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

        # --- Tages-Rollups: 30 bis 365 Tage zurück ---
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

        # --- Security-Feed: 50 Threat-Events in den letzten 48h ---
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

        counts = (
            db.query(AnalyticsSnapshot).count(),
            db.query(AnalyticsHourly).count(),
            db.query(AnalyticsDaily).count(),
            db.query(ThreatEvent).count(),
        )
        print(
            f"Demo-Daten erzeugt in {DB_PATH}\n"
            f"  Snapshots: {counts[0]} | Stunden-Rollups: {counts[1]} | "
            f"Tages-Rollups: {counts[2]} | Security-Events: {counts[3]}"
        )
    finally:
        db.close()


if __name__ == "__main__":
    main()
