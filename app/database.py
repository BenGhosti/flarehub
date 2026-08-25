"""
FlareHub – Datenbank-Setup (SQLite via SQLAlchemy).
"""
from datetime import datetime, timedelta

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, Text
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings

engine = create_engine(
    f"sqlite:///{settings.DATABASE_PATH}",
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class AnalyticsSnapshot(Base):
    """Ein Datenpunkt der Zonen-Analytics für einen Zeitraum (jeweils COLLECTOR_INTERVAL_MINUTES)."""
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


class ThreatEvent(Base):
    """Einzelner geblockter Request (WAF / Firewall) für den Security-Feed."""
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
    """Zuletzt bekannter Zustand von Zone-Settings, um UI-State zu cachen."""
    __tablename__ = "zone_setting_state"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, index=True)  # z.B. "development_mode", "security_level"
    value = Column(String)
    updated_at = Column(DateTime, default=datetime.utcnow)


class WebAuthnCredential(Base):
    """Registrierte Passkeys/YubiKeys."""
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
    """Für Rate-Limiting und PIN-Lockout."""
    __tablename__ = "login_attempts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    method = Column(String)  # pin, passkey
    success = Column(Boolean, default=False)
    ip_address = Column(String, nullable=True)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def cleanup_old_data(db, retention_days: int):
    """Löscht Analytics-Snapshots und Threat-Events älter als retention_days."""
    cutoff = datetime.utcnow() - timedelta(days=retention_days)
    db.query(AnalyticsSnapshot).filter(AnalyticsSnapshot.timestamp < cutoff).delete()
    db.query(ThreatEvent).filter(ThreatEvent.timestamp < cutoff).delete()
    db.commit()
