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
# Database Setup
# -----------------------------

DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

app = FastAPI(title="HomeSecurity Platform API", version="6.0.0")

# -----------------------------
# Database Models
# -----------------------------

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True, index=True)
    agent_id = Column(String)
    risk_score = Column(String)
    severity = Column(String)
    fingerprint = Column(String)
    timestamp = Column(String)

class Report(Base):
    __tablename__ = "reports"

    id = Column(String, primary_key=True, index=True)
    agent_id = Column(String)
    data = Column(Text)
    timestamp = Column(String)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True, index=True)
    agent_id = Column(String)
    risk_score = Column(String)
    severity = Column(String)
    timestamp = Column(String)


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

    # -------------------------
    # Get Previous Report
    # -------------------------

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

    # Detect new + MAC changes
    for ip, mac in current_devices.items():
        if ip not in previous_devices:
            new_devices.append({"ip": ip, "mac": mac})
        elif previous_devices[ip] != mac:
            mac_changes.append({
                "ip": ip,
                "old_mac": previous_devices[ip],
                "new_mac": mac
            })

    # Detect missing
    for ip, mac in previous_devices.items():
        if ip not in current_devices:
            missing_devices.append({"ip": ip, "mac": mac})

    # -------------------------
    # Risk Scoring Engine
    # -------------------------

    risk_score = 0


    if mac_changes:
        risk_score += 100


    risk_score += 40 * len(new_devices)


    risk_score += 15 * len(missing_devices)

    # Escalation for consecutive missing
    if missing_devices:
        recent_reports = (
            db.query(Report)
            .filter(Report.agent_id == report.agent_id)
            .order_by(Report.timestamp.desc())
            .limit(3)
            .all()
        )

        consecutive_missing = 0

        for past_report in recent_reports:
            past_devices = {
                d["ip"]: d["mac"]
                for d in json.loads(past_report.data)
            }

            if any(ip not in past_devices for ip, _ in [(d["ip"], d["mac"]) for d in missing_devices]):
                consecutive_missing += 1

        if consecutive_missing >= 2:
            risk_score += 60

    # Determine severity
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

    # -------------------------
    # Store Report (ALWAYS)
    # -------------------------

    new_report = Report(
        id=str(uuid.uuid4()),
        agent_id=report.agent_id,
        data=json.dumps(report.devices),
        timestamp=datetime.utcnow().isoformat()
    )

    db.add(new_report)

    # -------------------------
    # Alert Suppression Logic
    # -------------------------

    SUPPRESSION_MINUTES = 10

    latest_alert = (
        db.query(Alert)
        .filter(Alert.agent_id == report.agent_id)
        .order_by(Alert.timestamp.desc())
        .first()
    )

    store_alert = True

    if latest_alert:
        last_time = datetime.fromisoformat(latest_alert.timestamp)
        now = datetime.utcnow()

        within_window = (now - last_time).total_seconds() < SUPPRESSION_MINUTES * 60
        same_severity = latest_alert.severity == severity
        same_score = latest_alert.risk_score == str(risk_score)

        if within_window and same_severity and same_score:
            store_alert = False

    if store_alert:
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

# -----------------------------
# Alert Endpoints (Order Matters)
# -----------------------------

@app.get("/alerts")
def get_all_alerts():
    db = SessionLocal()
    alerts = db.query(Alert).order_by(Alert.timestamp.desc()).all()
    db.close()

    return [
        {
            "agent_id": alert.agent_id,
            "risk_score": alert.risk_score,
            "severity": alert.severity,
            "timestamp": alert.timestamp
        }
        for alert in alerts
    ]


@app.get("/alerts/summary")
def get_alert_summary():
    db = SessionLocal()

    alerts = db.query(Alert).all()
    db.close()

    summary = {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

    for alert in alerts:
        if alert.severity in summary:
            summary[alert.severity] += 1

    return summary


@app.get("/alerts/summary/{agent_id}")
def get_alert_summary_by_agent(agent_id: str):
    db = SessionLocal()
    alerts = db.query(Alert).filter(Alert.agent_id == agent_id).all()
    db.close()

    summary = {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

    for alert in alerts:
        if alert.severity in summary:
            summary[alert.severity] += 1

    return summary




@app.get("/alerts/trend/{agent_id}/{hours}")
def get_agent_alert_trend(agent_id: str, hours: int):
    db = SessionLocal()
    alerts = db.query(Alert).filter(Alert.agent_id == agent_id).all()
    db.close()

    cutoff = datetime.utcnow() - timedelta(hours=hours)

    summary = {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

    for alert in alerts:
        alert_time = datetime.fromisoformat(alert.timestamp)
        if alert_time >= cutoff and alert.severity in summary:
            summary[alert.severity] += 1

    return {"agent_id": agent_id, "window_hours": hours, "summary": summary}


@app.get("/alerts/trend/{hours}")
def get_alert_trend(hours: int):
    db = SessionLocal()

    alerts = db.query(Alert).all()
    db.close()

    cutoff = datetime.utcnow() - timedelta(hours=hours)

    summary = {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

    for alert in alerts:
        alert_time = datetime.fromisoformat(alert.timestamp)
        if alert_time >= cutoff and alert.severity in summary:
            summary[alert.severity] += 1

    return {"window_hours": hours, "summary": summary}


@app.get("/alerts/{agent_id}")
def get_alerts_by_agent(agent_id: str):
    db = SessionLocal()

    alerts = (
        db.query(Alert)
        .filter(Alert.agent_id == agent_id)
        .order_by(Alert.timestamp.desc())
        .all()
    )

    db.close()

    return [
        {
            "agent_id": alert.agent_id,
            "risk_score": alert.risk_score,
            "severity": alert.severity,
            "timestamp": alert.timestamp
        }
        for alert in alerts
    ]

# TEMPORARY ADMIN ROUTE — SAFE RESET
@app.get("/admin/reset-alerts")
def reset_alerts():
    try:
        Alert.__table__.drop(engine, checkfirst=True)
        Alert.__table__.create(engine, checkfirst=True)
        return {"message": "Alerts table reset successfully"}
    except Exception as e:
        return {"error": str(e)}



