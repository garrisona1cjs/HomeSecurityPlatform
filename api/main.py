from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
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

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

app = FastAPI(title="HomeSecurity Platform API", version="15.0.0")

# -----------------------------
# Vendor Lookup
# -----------------------------

mac_lookup = MacLookup()
try:
    mac_lookup.update_vendors()
except:
    pass

def get_vendor(mac):
    try:
        return mac_lookup.lookup(mac)
    except:
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

def verify_agent(db, agent_id: str, api_key: str):
    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent or agent.api_key != api_key:
        raise HTTPException(status_code=401, detail="Invalid agent")

# -----------------------------
# Register Agent
# -----------------------------

@app.post("/register")
def register_agent(agent: AgentRegistration):
    db = SessionLocal()

    agent_id = str(uuid.uuid4())
    api_key = secrets.token_hex(32)

    db.add(Agent(
        agent_id=agent_id,
        hostname=agent.hostname,
        ip_address=agent.ip_address,
        api_key=api_key
    ))

    db.commit()
    db.close()

    return {"agent_id": agent_id, "api_key": api_key}

# -----------------------------
# Report Devices
# -----------------------------

@app.post("/report")
def report_devices(report: DeviceReport, x_api_key: str = Header(None)):
    db = SessionLocal()
    verify_agent(db, report.agent_id, x_api_key)

    devices = []
    rogue = False

    for d in report.devices:
        vendor = get_vendor(d["mac"])
        if vendor == "Unknown":
            rogue = True
        devices.append({"ip": d["ip"], "mac": d["mac"], "vendor": vendor})

    risk_score = 40 * len(devices)
    if rogue:
        risk_score += 120

    if risk_score >= 120:
        severity = "CRITICAL"
    elif risk_score >= 80:
        severity = "HIGH"
    elif risk_score >= 40:
        severity = "MEDIUM"
    elif risk_score > 0:
        severity = "LOW"
    else:
        severity = "INFO"

    db.add(Report(
        id=str(uuid.uuid4()),
        agent_id=report.agent_id,
        data=json.dumps(devices),
        timestamp=datetime.utcnow().isoformat()
    ))

    if risk_score > 0:
        db.add(Alert(
            id=str(uuid.uuid4()),
            agent_id=report.agent_id,
            risk_score=str(risk_score),
            severity=severity,
            timestamp=datetime.utcnow().isoformat()
        ))

    db.commit()
    db.close()

    return {"risk_score": risk_score, "severity": severity}

# -----------------------------
# Alerts API
# -----------------------------

@app.get("/alerts")
def get_alerts():
    db = SessionLocal()
    alerts = db.query(Alert).order_by(Alert.timestamp.desc()).all()
    db.close()
    return alerts

# -----------------------------
# Agent Status API
# -----------------------------

@app.get("/agents/status")
def agent_status():
    db = SessionLocal()
    agents = db.query(Agent).all()
    results = []

    for agent in agents:
        last_report = (
            db.query(Report)
            .filter(Report.agent_id == agent.agent_id)
            .order_by(Report.timestamp.desc())
            .first()
        )

        status = "OFFLINE"
        last_seen = None

        if last_report:
            last_seen = last_report.timestamp
            last_time = datetime.fromisoformat(last_seen)
            minutes = (datetime.utcnow() - last_time).total_seconds() / 60

            if minutes < 5:
                status = "ONLINE"
            elif minutes < 60:
                status = "IDLE"

        results.append({
            "agent_id": agent.agent_id,
            "hostname": agent.hostname,
            "ip": agent.ip_address,
            "status": status,
            "last_seen": last_seen
        })

    db.close()
    return results

# -----------------------------
# Dashboard
# -----------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
<html>
<head>
<title>HomeSecurity SOC Dashboard</title>
<style>
body {font-family: Arial; background:#0f172a; color:white; padding:20px;}
.card {background:#020617; padding:15px; margin:10px; border-radius:8px;}
.online {color:#22c55e;}
.idle {color:#facc15;}
.offline {color:#ef4444;}
</style>
</head>
<body>

<h1>🛡 SOC Dashboard</h1>

<h2>Agent Status</h2>
<div id="agents"></div>

<script>





async function load(){
 const agents = await fetch('/agents/status').then(r=>r.json());

 document.getElementById("agents").innerHTML =
 agents.map(a =>
 `<div class="card">
   <b>${a.hostname}</b> (${a.ip})<br>
   Status: <span class="${
     a.status=="ONLINE"?"online":
     a.status=="IDLE"?"idle":"offline"
   }">${a.status}</span><br>
   Last Seen: ${a.last_seen || "Never"}
 </div>`
 ).join("");
}

load();
setInterval(load,5000);
</script>
</body>
</html>
"""





