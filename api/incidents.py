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
def update_incident_status(incident_id: str, status: str, db: Session = Depends(get_db)):
    
    incident = db.query(Incident).filter(Incident.id == incident_id).first()

    if not incident:
        return {"error": "Incident not found"}

    incident.status = status
    incident.updated_at = datetime.utcnow()

    db.commit()

    return {"message": "Status updated", "incident_id": incident_id, "status": status}


# ======================================================
# ASSIGN INCIDENT
# ======================================================

@router.post("/incidents/{incident_id}/assign")
def assign_incident(incident_id: str, analyst: str, db: Session = Depends(get_db)):

    incident = db.query(Incident).filter(Incident.id == incident_id).first()

    if not incident:
        return {"error": "Incident not found"}

    incident.assigned_to = analyst
    incident.last_updated = datetime.utcnow()

    db.commit()

    return {"message": "Incident assigned", "incident_id": incident_id, "assigned_to": analyst}


# ======================================================
# GET INCIDENTS SORTED BY PRIORITY
# ======================================================

@router.get("/incidents/priority")
def get_priority_incidents(db: Session = Depends(get_db)):

    incidents = db.query(Incident).order_by(Incident.priority.desc()).all()

    return incidents