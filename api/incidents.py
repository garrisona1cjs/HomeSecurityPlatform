from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from datetime import datetime

from .database import get_db
from .models import Incident

import uuid
from .models import IncidentAudit

router = APIRouter()

# ======================================================
# UPDATE INCIDENT STATUS
# ======================================================

@router.post("/incidents/{incident_id}/status")
def update_incident_status(
    incident_id: str,
    status: str,
    analyst: str = None,
    db: Session = Depends(get_db)
):

    incident = db.query(Incident).filter(Incident.id == incident_id).first()

    if not incident:
        return {"error": "Incident not found"}

    # 🔒 ENFORCE OWNERSHIP
    if incident.assigned_to:
        if not analyst:
            return {"error": "analyst required", "assigned_to": incident.assigned_to}

        if incident.assigned_to != analyst:
            return {
                "error": "not owner",
                "assigned_to": incident.assigned_to
            }
    
    old_status = incident.status

    incident.status = status
    incident.updated_at = datetime.utcnow()

    audit = IncidentAudit(
        id=str(uuid.uuid4()),
        incident_id=incident.id,
        action="STATUS_CHANGE",
        actor=analyst,
        old_value=old_status,
        new_value=status
    )

    db.add(audit)

    db.commit()

    return {
        "message": "Status updated",
        "incident_id": incident_id,
        "status": status
    }


# ======================================================
# ASSIGN INCIDENT
# ======================================================

@router.post("/incidents/{incident_id}/assign")
def assign_incident(incident_id: str, analyst: str, db: Session = Depends(get_db)):

    incident = db.query(Incident).filter(Incident.id == incident_id).first()

    if not incident:
        return {"error": "Incident not found"}

    # 🔒 PREVENT TAKEOVER
    if incident.assigned_to and incident.assigned_to != analyst:
        return {
            "error": "incident already assigned",
            "assigned_to": incident.assigned_to
        }

    incident.assigned_to = analyst

    # 🔄 AUTO MOVE INTO INVESTIGATING
    if incident.status == "NEW":
        incident.status = "INVESTIGATING"

    incident.updated_at = datetime.utcnow()

    audit = IncidentAudit(
        id=str(uuid.uuid4()),
        incident_id=incident.id,
        action="ASSIGNED",
        actor=analyst,
        old_value=None,
        new_value=analyst
    )

    db.add(audit)

    db.commit()

    return {
        "message": "Incident assigned",
        "incident_id": incident_id,
        "assigned_to": analyst
    }


# ======================================================
# GET INCIDENTS SORTED BY PRIORITY
# ======================================================

@router.get("/incidents/priority")
def get_priority_incidents(db: Session = Depends(get_db)):

    incidents = db.query(Incident).order_by(Incident.priority.desc()).all()

    return [
    {
        "id": i.id,
        "lat": i.lat,
        "lng": i.lng,
        "count": i.count,
        "risk": i.risk,
        "priority": i.priority,
        "status": i.status,

        "sla_deadline": i.sla_deadline,
        "last_seen": i.last_seen,

        # 🔥 ADD THESE
        "threat_type": i.threat_type,
        "recommended_action": i.recommended_action,
        "confidence": i.confidence
    }
    for i in incidents
]

@router.get("/incidents/{incident_id}/audit")
def get_incident_audit(incident_id: str, db: Session = Depends(get_db)):

    logs = db.query(IncidentAudit).filter(
        IncidentAudit.incident_id == incident_id
    ).order_by(IncidentAudit.timestamp.desc()).all()

    return [
        {
            "action": l.action,
            "actor": l.actor,
            "old": l.old_value,
            "new": l.new_value,
            "timestamp": l.timestamp
        }
        for l in logs
    ]

# ======================================================
# GET INCIDENT ALERTS (INTELLIGENCE FEED)
# ======================================================

@router.get("/incidents/{incident_id}/alerts")
def get_incident_alerts(incident_id: str, db: Session = Depends(get_db)):

    from sqlalchemy import text

    result = db.execute(text("""
        SELECT severity,
               technique,
               latitude,
               longitude,
               country_code,
               origin_label,
               timestamp
        FROM alerts
        WHERE incident_id = :id
        ORDER BY timestamp DESC
        LIMIT 100
    """), {"id": incident_id})

    rows = result.fetchall()

    return [
        {
            "severity": r[0],
            "technique": r[1],
            "latitude": float(r[2]) if r[2] else 0,
            "longitude": float(r[3]) if r[3] else 0,
            "country_code": r[4],
            "origin_label": r[5],
            "timestamp": str(r[6])
        }
        for r in rows
    ]