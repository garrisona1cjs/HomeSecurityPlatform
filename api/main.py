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

app = FastAPI(title="HomeSecurity Platform API", version="11.0.0")

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

    last_report = db.query(Report).filter(
        Report.agent_id == report.agent_id
    ).order_by(Report.timestamp.desc()).first()

    previous = {}
    if last_report:
        for d in json.loads(last_report.data):
            previous[d["ip"]] = d

    current = {}
    for d in report.devices:
        vendor = get_vendor(d["mac"])
        current[d["ip"]] = {"ip": d["ip"], "mac": d["mac"], "vendor": vendor}

    new_devices, missing_devices = [], []

    for ip, data in current.items():
        if ip not in previous:
            new_devices.append(data)

    for ip in previous:
        if ip not in current:
            missing_devices.append(ip)

    SAFE_VENDORS = ["Apple","Samsung","Intel","Dell","HP","Cisco","Microsoft","Google","Amazon","Raspberry"]

    rogue_devices = []
    for d in new_devices:
        vendor = d["vendor"]
        if vendor == "Unknown":
            rogue_devices.append({"ip": d["ip"], "reason": "Unknown vendor"})
        elif not any(v.lower() in vendor.lower() for v in SAFE_VENDORS):
            rogue_devices.append({"ip": d["ip"], "vendor": vendor, "reason": "Unrecognized vendor"})

    risk_score = 40*len(new_devices) + 15*len(missing_devices)
    if rogue_devices:
        risk_score += 120

    severity = "INFO"
    if risk_score >= 120:
        severity = "CRITICAL"
    elif risk_score >= 80:
        severity = "HIGH"
    elif risk_score >= 40:
        severity = "MEDIUM"
    elif risk_score > 0:
        severity = "LOW"

    db.add(Report(
        id=str(uuid.uuid4()),
        agent_id=report.agent_id,
        data=json.dumps(list(current.values())),
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
# Dashboard
# -----------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
<html>
<head>
<title>HomeSecurity SOC Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>
body {font-family: Arial; background:#0f172a; color:white; padding:20px; overflow-x:hidden;}

.ticker {
    width:100%;
    overflow:hidden;
    white-space:nowrap;
    background:#020617;
    border-bottom:2px solid #ef4444;
    padding:8px 0;
}

.ticker span {
    display:inline-block;
    padding-left:100%;
    animation:ticker 20s linear infinite;
}

@keyframes ticker {
    0% { transform:translateX(0); }
    100% { transform:translateX(-100%); }
}

.critical {
    animation: pulse 1s infinite;
}

@keyframes pulse {
    0% { box-shadow:0 0 5px red; }
    50% { box-shadow:0 0 20px red; }
    100% { box-shadow:0 0 5px red; }
}
</style>
</head>

<body>

<div class="ticker">
<span id="tickerText">Loading alerts...</span>
</div>

<h1>🛡 HomeSecurity SOC Dashboard</h1>

<h2>Recent Alerts</h2>
<div id="alerts"></div>

<script>
function severityColor(severity){
    if(severity=="CRITICAL") return "#ef4444";
    if(severity=="HIGH") return "#f97316";
    if(severity=="MEDIUM") return "#eab308";
    if(severity=="LOW") return "#3b82f6";
    return "#22c55e";
}

async function loadAlerts(){
    const alerts = await fetch('/alerts').then(r=>r.json());

    document.getElementById("alerts").innerHTML =
        alerts.slice(0,5).map(a=>{
            const color = severityColor(a.severity);
            const pulse = a.severity=="CRITICAL" ? "critical" : "";
            return `<div class="${pulse}" style="
                margin:6px 0;
                padding:8px;
                border-left:6px solid ${color};
                background:${color}20;
                border-radius:6px;">
                <strong>${a.severity}</strong> — Risk ${a.risk_score}
            </div>`;
        }).join("");

    document.getElementById("tickerText").innerHTML =
        alerts.slice(0,10).map(a =>
            `${a.severity} threat (score ${a.risk_score}) detected`
        ).join("   ⚠   ");
}

loadAlerts();
setInterval(loadAlerts, 5000);
</script>
</body>
</html>
"""





