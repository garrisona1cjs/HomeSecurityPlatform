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

from mac_vendor_lookup import MacLookup

# -----------------------------
# Database Setup
# -----------------------------

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable not set")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=300
)

SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

app = FastAPI(title="HomeSecurity Platform API", version="7.0.0")

# -----------------------------
# Vendor Lookup Setup
# -----------------------------

mac_lookup = MacLookup()
try:
    mac_lookup.update_vendors()
except:
    pass

def get_vendor(mac):
    try:
        return mac_lookup.lookup(mac)
    except Exception:
        return "Unknown"

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
    agent_id = Column(String, index=True)
    risk_score = Column(String)
    severity = Column(String)
    timestamp = Column(String, index=True)


class Report(Base):
    __tablename__ = "reports"

    id = Column(String, primary_key=True, index=True)
    agent_id = Column(String, index=True)
    data = Column(Text)
    timestamp = Column(String, index=True)


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
# Register Agent
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

# -----------------------------
# Report Devices
# -----------------------------

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
        previous_devices = {
            d["ip"]: {
                "mac": d["mac"],
                "vendor": d.get("vendor", "Unknown")
            }
            for d in previous_data
        }

    current_devices = {}
    for d in report.devices:
        vendor = get_vendor(d["mac"])
        current_devices[d["ip"]] = {
            "mac": d["mac"],
            "vendor": vendor
        }

    new_devices = []
    missing_devices = []
    mac_changes = []
    vendor_changes = []

    for ip, data in current_devices.items():
        if ip not in previous_devices:
            new_devices.append({"ip": ip, **data})
        else:
            if previous_devices[ip]["mac"] != data["mac"]:
                mac_changes.append({"ip": ip})
            if previous_devices[ip]["vendor"] != data["vendor"]:
                vendor_changes.append({
                    "ip": ip,
                    "old_vendor": previous_devices[ip]["vendor"],
                    "new_vendor": data["vendor"]
                })

    for ip in previous_devices:
        if ip not in current_devices:
            missing_devices.append({"ip": ip})

   # -----------------------------
# Rogue Device Detection
# -----------------------------

KNOWN_SAFE_VENDORS = [
    "Apple",
    "Samsung",
    "Intel",
    "Dell",
    "HP",
    "Cisco",
    "Microsoft",
    "Google",
    "Amazon",
    "Raspberry"
]

rogue_devices = []

for device in new_devices:
    vendor = device["vendor"]

    if vendor == "Unknown":
        rogue_devices.append({
            "ip": device["ip"],
            "reason": "Unknown vendor"
        })

    elif not any(safe.lower() in vendor.lower() for safe in KNOWN_SAFE_VENDORS):
        rogue_devices.append({
            "ip": device["ip"],
            "vendor": vendor,
            "reason": "Unrecognized vendor"
        })

# -----------------------------
# Risk scoring
# -----------------------------

risk_score = 0

risk_score += 40 * len(new_devices)
risk_score += 15 * len(missing_devices)

if mac_changes:
    risk_score += 100

if vendor_changes:
    risk_score += 60

# 🚨 Rogue devices increase risk significantly
if rogue_devices:
    risk_score += 120

# -----------------------------
# Severity Levels
# -----------------------------

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
    "mac_changes": mac_changes,
    "vendor_changes": vendor_changes,
    "rogue_devices": rogue_devices
    }

    new_report = Report(
        id=str(uuid.uuid4()),
        agent_id=report.agent_id,
        data=json.dumps([
            {"ip": ip, "mac": data["mac"], "vendor": data["vendor"]}
            for ip, data in current_devices.items()
        ]),
        timestamp=datetime.utcnow().isoformat()
    )

    db.add(new_report)

    if risk_score > 0:
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
# Alerts
# -----------------------------

@app.get("/alerts")
def get_alerts():
    db = SessionLocal()
    alerts = db.query(Alert).order_by(Alert.timestamp.desc()).all()
    db.close()

    return [
        {
            "agent_id": a.agent_id,
            "risk_score": a.risk_score,
            "severity": a.severity,
            "timestamp": a.timestamp
        }
        for a in alerts
    ]

# =============================
# ANALYTICS ENDPOINTS
# =============================

@app.get("/analytics/summary")
def analytics_summary():
    db = SessionLocal()

    total_agents = db.query(Agent).count()
    total_alerts = db.query(Alert).count()
    total_reports = db.query(Report).count()

    severity_counts = {"INFO":0,"LOW":0,"MEDIUM":0,"HIGH":0,"CRITICAL":0}

    alerts = db.query(Alert).all()
    for alert in alerts:
        if alert.severity in severity_counts:
            severity_counts[alert.severity] += 1

    db.close()

    return {
        "total_agents": total_agents,
        "total_reports": total_reports,
        "total_alerts": total_alerts,
        "severity_breakdown": severity_counts
    }


@app.get("/analytics/agent-health")
def agent_health():
    db = SessionLocal()

    agents = db.query(Agent).all()
    health = []

    for agent in agents:
        last_report = (
            db.query(Report)
            .filter(Report.agent_id == agent.agent_id)
            .order_by(Report.timestamp.desc())
            .first()
        )

        status = "offline"

        if last_report:
            last_seen = datetime.fromisoformat(last_report.timestamp)
            minutes = (datetime.utcnow() - last_seen).total_seconds() / 60

            if minutes < 5:
                status = "online"
            elif minutes < 60:
                status = "idle"

        health.append({
            "agent_id": agent.agent_id,
            "hostname": agent.hostname,
            "ip": agent.ip_address,
            "status": status,
            "last_seen": last_report.timestamp if last_report else None
        })

    db.close()
    return health


@app.get("/analytics/risk-trend/{hours}")
def risk_trend(hours: int):
    db = SessionLocal()

    cutoff = datetime.utcnow() - timedelta(hours=hours)
    alerts = db.query(Alert).all()

    trend = []

    for alert in alerts:
        alert_time = datetime.fromisoformat(alert.timestamp)
        if alert_time >= cutoff:
            trend.append({
                "time": alert.timestamp,
                "risk_score": alert.risk_score,
                "severity": alert.severity
            })

    db.close()
    return trend


@app.get("/analytics/top-risk-agents")
def top_risk_agents():
    db = SessionLocal()

    alerts = db.query(Alert).all()
    risk_totals = {}

    for alert in alerts:
        risk_totals.setdefault(alert.agent_id, 0)
        risk_totals[alert.agent_id] += int(alert.risk_score)

    db.close()

    sorted_agents = sorted(
        risk_totals.items(),
        key=lambda x: x[1],
        reverse=True
    )

    return [{"agent_id": aid, "total_risk": score} for aid, score in sorted_agents]




