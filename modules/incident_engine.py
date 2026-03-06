# modules/incident_engine.py

from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from models import Incident

# correlation window (seconds)
CORRELATION_WINDOW = 120


def find_existing_incident(db: Session, source_ip: str, asn: str):
    """
    Check if an incident already exists for this source
    within the correlation window.
    """

    window_start = datetime.utcnow() - timedelta(seconds=CORRELATION_WINDOW)

    incident = (
        db.query(Incident)
        .filter(Incident.source_ip == source_ip)
        .filter(Incident.asn == asn)
        .filter(Incident.last_seen >= window_start)
        .first()
    )

    return incident


def create_incident(db: Session, alert_data: dict):
    """
    Create a new incident record.
    """

    incident = Incident(
        source_ip=alert_data["source_ip"],
        asn=alert_data["asn"],
        country=alert_data["country"],
        severity=alert_data["severity"],
        alert_count=1,
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        status="NEW",
    )

    db.add(incident)
    db.commit()
    db.refresh(incident)

    return incident


def update_incident(db: Session, incident: Incident):
    """
    Update incident when a new correlated alert appears.
    """

    incident.alert_count += 1
    incident.last_seen = datetime.utcnow()

    db.commit()

    return incident