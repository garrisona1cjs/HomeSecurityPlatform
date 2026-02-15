from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import List
import uuid
import secrets
import os
import json

from sqlalchemy import create_engine, Column, String, Text
from sqlalchemy.orm import declarative_base, sessionmaker

# -----------------------------
# Database Setup (Render Ready)
# -----------------------------

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is not set")

# Force SSL if not already present (Render requires it)
if "sslmode" not in DATABASE_URL:
    DATABASE_URL += "?sslmode=require"

print("✅ DATABASE_URL loaded")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=300,
)

SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

app = FastAPI(title="HomeSecurity Platform API", version="6.0.0")

# -----------------------------
# Database Models
# -----------------------------

class Agent(Base):
    __tablename__ = "agents"

    agent_id = Column(String, primary_key=True, index=True)
    hostname = Column(String)
    ip_address = Column(String)
    api_key = Column(String)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True, index=True)
    agent_id = Column(String)
    risk_score = Column(String)
    severity = Column(String)

    timestamp = Column(String)


class Report(Base):
    __tablename__ = "reports"

    id = Column(String, primary_key=True, index=True)
    agent_id = Column(String)
    data = Column(Text)
    timestamp = Column(String)


# Create tables safely
Base.metadata.create_all(bind=engine)

# -----------------------------
# Schemas
# -----------------------------

class AgentRegistration(BaseModel):
    hostname: str
    ip_address: str


class DeviceReport(BaseModel):
    agent_id: str
    devices: List[dict]


# -----------------------------
# Auth
# -----------------------------

def verify_agent(db, agent_id: str, x_api_key: str):
    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent or agent.api_key != x_api_key:
        raise HTTPException(status_code=401, detail="Invalid agent")
    return agent


# -----------------------------
# Endpoints
# -----------------------------

@app.get("/")
def root():
    return {"status": "HomeSecurityPlatform running"}


@app.post("/register")
def register_agent(agent: AgentRegistration):
    db = SessionLocal()

    agent_id = str(uuid.uuid4())
    api_key = secrets.token_hex(32)

    new_agent = Agent(
        agent_id=agent_id,
        hostname=agent.hostname,
        ip_address=agent.ip_address,
        api_key=api_key
    )

    db.add(new_agent)
    db.commit()
    db.close()

    return {
        "agent_id": agent_id,
        "api_key": api_key,
        "message": "Agent registered successfully"
    }


@app.post("/report")
def report_devices(report: DeviceReport, x_api_key: str = Header(None)):
    db = SessionLocal()

    verify_agent(db, report.agent_id, x_api_key)



    last_report = (
        db.query(Report)
        .filter(Report.agent_id == report.agent_id)
        .order_by(Report.timestamp.desc())
        .first()
    )

    previous_devices = {}
    if last_report:
        previous_data = json.loads(last_report.data)
        previous_devices = {d["ip"]: d["mac"] for d in previous_data}

    current_devices = {d["ip"]: d["mac"] for d in report.devices}

    new_devices = []
    missing_devices = []
    mac_changes = []


    for ip, mac in current_devices.items():
        if ip not in previous_devices:
            new_devices.append({"ip": ip, "mac": mac})
        elif previous_devices[ip] != mac:
            mac_changes.append({
                "ip": ip,
                "old_mac": previous_devices[ip],
                "new_mac": mac
            })


    for ip, mac in previous_devices.items():
        if ip not in current_devices:
            missing_devices.append({"ip": ip, "mac": mac})



    risk_score = 0


    if mac_changes:
        risk_score += 100


    risk_score += 40 * len(new_devices)


    risk_score += 15 * len(missing_devices)


    if risk_score == 0:
        severity = "INFO"
    elif risk_score < 40:
        severity = "LOW"
    elif risk_score < 80:
        severity = "MEDIUM"
    elif risk_score < 120:
        severity = "HIGH"
    else:
        severity = "CRITICAL"

    change_summary = {
        "risk_score": risk_score,
        "severity": severity,
        "new_devices": new_devices,
        "missing_devices": missing_devices,
        "mac_changes": mac_changes
    }
    

    new_report = Report(
        id=str(uuid.uuid4()),
        agent_id=report.agent_id,
        data=json.dumps(report.devices),
        timestamp=datetime.utcnow().isoformat()
    )

    db.add(new_report)

    new_alert = Alert(
        id=str(uuid.uuid4()),
        agent_id=report.agent_id,
        risk_score=str(risk_score),
        severity=severity,
        timestamp=datetime.utcnow().isoformat()
    )

    db.add(new_alert)

    db.commit()
    db.close()

    return {
        "message": "Report stored successfully",
        "changes": change_summary
    }



@app.get("/alerts")
def get_alerts():
    db = SessionLocal()
    alerts = db.query(Alert).order_by(Alert.timestamp.desc()).all()
    db.close()
    return alerts


@app.get("/alerts/{agent_id}")
def get_agent_alerts(agent_id: str):
    db = SessionLocal()
    alerts = db.query(Alert).filter(Alert.agent_id == agent_id).all()
    db.close()
    return alerts


# -----------------------------
# ADMIN RESET ROUTE
# -----------------------------

@app.get("/admin/reset-alerts")
def reset_alerts():
    Alert.__table__.drop(engine, checkfirst=True)
    Alert.__table__.create(engine, checkfirst=True)
    return {"message": "Alerts table reset"}




