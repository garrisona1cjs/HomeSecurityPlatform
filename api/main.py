from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
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

# =============================
# DATABASE
# =============================

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable not set")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

app = FastAPI(title="LayerSeven Security API", version="9.0.0")

# serve logo/static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# =============================
# VENDOR LOOKUP
# =============================

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

# =============================
# DATABASE MODELS
# =============================

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

# =============================
# SCHEMAS
# =============================

class AgentRegistration(BaseModel):
    hostname: str
    ip_address: str

class DeviceReport(BaseModel):
    agent_id: str
    devices: List[dict]

# =============================
# AUTH
# =============================

def verify_agent(db, agent_id: str, api_key: str):
    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent or agent.api_key != api_key:
        raise HTTPException(status_code=401, detail="Invalid agent")

# =============================
# REGISTER AGENT
# =============================

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

    return {
        "agent_id": agent_id,
        "api_key": api_key,
        "message": "Agent registered successfully"
    }

# =============================
# REPORT DEVICES
# =============================

@app.post("/report")
def report_devices(report: DeviceReport, x_api_key: str = Header(None)):
    db = SessionLocal()
    verify_agent(db, report.agent_id, x_api_key)

    last_report = db.query(Report).filter(
        Report.agent_id == report.agent_id
    ).order_by(Report.timestamp.desc()).first()

    previous_devices = {}
    if last_report:
        for d in json.loads(last_report.data):
            previous_devices[d["ip"]] = d

    current_devices = {}

    for d in report.devices:
        vendor = get_vendor(d["mac"])
        current_devices[d["ip"]] = {
            "ip": d["ip"],
            "mac": d["mac"],
            "vendor": vendor
        }

    new_devices = []
    missing_devices = []
    mac_changes = []
    vendor_changes = []

    for ip, data in current_devices.items():
        if ip not in previous_devices:
            new_devices.append(data)
        else:
            if previous_devices[ip]["mac"] != data["mac"]:
                mac_changes.append(ip)
            if previous_devices[ip]["vendor"] != data["vendor"]:
                vendor_changes.append(ip)

    for ip in previous_devices:
        if ip not in current_devices:
            missing_devices.append(ip)

    # Rogue detection
    SAFE_VENDORS = ["Apple","Samsung","Intel","Dell","HP","Cisco","Microsoft","Google","Amazon","Raspberry"]
    rogue_devices = []

    for d in new_devices:
        vendor = d["vendor"]
        if vendor == "Unknown":
            rogue_devices.append({"ip": d["ip"], "reason": "Unknown vendor"})
        elif not any(v.lower() in vendor.lower() for v in SAFE_VENDORS):
            rogue_devices.append({"ip": d["ip"], "vendor": vendor, "reason": "Unrecognized vendor"})

    # Risk scoring
    risk_score = (
        40 * len(new_devices) +
        15 * len(missing_devices) +
        (100 if mac_changes else 0) +
        (60 if vendor_changes else 0) +
        (120 if rogue_devices else 0)
    )

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

    summary = {
        "risk_score": risk_score,
        "severity": severity,
        "new_devices": new_devices,
        "missing_devices": missing_devices,
        "mac_changes": mac_changes,
        "vendor_changes": vendor_changes,
        "rogue_devices": rogue_devices
    }

    db.add(Report(
        id=str(uuid.uuid4()),
        agent_id=report.agent_id,
        data=json.dumps(list(current_devices.values())),
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

    return {"message": "Report stored successfully", "changes": summary}

# =============================
# ALERTS API
# =============================

@app.get("/alerts")
def get_alerts():
    db = SessionLocal()
    alerts = db.query(Alert).order_by(Alert.timestamp.desc()).all()
    db.close()
    return alerts

@app.get("/analytics/summary")
def analytics_summary():
    db = SessionLocal()
    data = {
        "total_agents": db.query(Agent).count(),
        "total_reports": db.query(Report).count(),
        "total_alerts": db.query(Alert).count()
    }
    db.close()
    return data

@app.get("/analytics/risk-trend/{hours}")
def risk_trend(hours: int):
    db = SessionLocal()
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    alerts = db.query(Alert).all()
    db.close()

    return [
        {"time": a.timestamp, "risk_score": int(a.risk_score)}
        for a in alerts
        if datetime.fromisoformat(a.timestamp) >= cutoff
    ]

# =============================
# SOC DASHBOARD
# =============================

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
<html>
<head>
<title>LayerSeven Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

</head>

<body style="background:#0f172a;color:white;font-family:Arial;padding:20px">

<img src="/static/logo.png" height="60">

<h1>🛡 LayerSeven Security Dashboard</h1>

<div id="ticker" style="background:black;padding:10px;margin-bottom:20px"></div>

<h2>System Summary</h2>
<div id="summary">Loading...</div>

<h2>Recent Alerts</h2>
<div id="alerts"></div>

<h2>Risk Trend</h2>
<canvas id="riskChart"></canvas>

<script>
function severityColor(level){
    if(level=="CRITICAL") return "red";
    if(level=="HIGH") return "orange";
    if(level=="MEDIUM") return "yellow";
    if(level=="LOW") return "cyan";
    return "white";
}

async function load(){
    const summary = await fetch('/analytics/summary').then(r=>r.json());
    const alerts = await fetch('/alerts').then(r=>r.json());
    const trend = await fetch('/analytics/risk-trend/24').then(r=>r.json());

    document.getElementById("summary").innerHTML =
        "Agents: "+summary.total_agents+
        "<br>Reports: "+summary.total_reports+
        "<br>Alerts: "+summary.total_alerts;

    document.getElementById("alerts").innerHTML =
        alerts.slice(0,5).map(a =>
            `<div style="color:${severityColor(a.severity)}">
                ${a.severity} — Score ${a.risk_score}
            </div>`
        ).join("");

    document.getElementById("ticker").innerHTML =
        alerts.slice(0,5).map(a =>
            `<span style="margin-right:30px;color:${severityColor(a.severity)}">
            ⚠ ${a.severity} (${a.risk_score})
            </span>`
        ).join("");

    const ctx = document.getElementById('riskChart').getContext('2d');
    new Chart(ctx,{
        type:'line',
        data:{
            labels:trend.map(t=>new Date(t.time).toLocaleTimeString()),
            datasets:[{label:'Risk',data:trend.map(t=>t.risk_score)}]
        }
    });
}

load();
setInterval(load,10000);
</script>

</body>
</html>
"""






