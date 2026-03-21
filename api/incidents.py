from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from datetime import datetime

from .database import get_db
from .models import Incident

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

    incident.status = status
    incident.updated_at = datetime.utcnow()

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
        "assigned_to": i.assigned_to,
        "sla_deadline": i.sla_deadline,
        "escalation_level": i.escalation_level,
        "last_seen": i.last_seen
    }
    for i in incidents
]