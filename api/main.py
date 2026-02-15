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

# -----------------------------
# DATABASE
# -----------------------------

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

app = FastAPI(title="HomeSecurity Platform API", version="10.0")

# serve static files (logo)
app.mount("/static", StaticFiles(directory="static"), name="static")

# -----------------------------
# MAC Vendor Lookup
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
# DATABASE MODELS
# -----------------------------

class Agent(Base):
    __tablename__ = "agents"
    agent_id = Column(String, primary_key=True, index=True)
    hostname = Column(String)
    ip_address = Column(String)
    api_key = Column(String)

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(String, primary_key=True)
    agent_id = Column(String)
    risk_score = Column(String)
    severity = Column(String)
    timestamp = Column(String)

class Report(Base):
    __tablename__ = "reports"
    id = Column(String, primary_key=True)
    agent_id = Column(String)
    data = Column(Text)
    timestamp = Column(String)

Base.metadata.create_all(bind=engine)

# -----------------------------
# SCHEMAS
# -----------------------------

class AgentRegistration(BaseModel):
    hostname: str
    ip_address: str

class DeviceReport(BaseModel):
    agent_id: str
    devices: List[dict]

# -----------------------------
# AUTH
# -----------------------------

def verify_agent(db, agent_id, api_key):
    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent or agent.api_key != api_key:
        raise HTTPException(status_code=401, detail="Invalid agent")
    

# -----------------------------
# REGISTER AGENT
# -----------------------------

@app.post("/register")
def register(agent: AgentRegistration):
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
        "api_key": api_key
    }

# -----------------------------
# REPORT DEVICES
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
        for d in json.loads(last_report.data):
            previous_devices[d["ip"]] = d

    current_devices = {}

    for d in report.devices:

        current_devices[d["ip"]] = {
            "ip": d["ip"],
            "mac": d["mac"],
            "vendor": get_vendor(d["mac"])
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
    SAFE = ["Apple","Samsung","Intel","Dell","HP","Cisco","Microsoft","Google","Amazon","Raspberry"]

    rogue_devices = []

    for d in new_devices:
        if d["vendor"] == "Unknown":
            rogue_devices.append({"ip": d["ip"], "reason": "Unknown vendor"})
        elif not any(v.lower() in d["vendor"].lower() for v in SAFE):
            rogue_devices.append({"ip": d["ip"], "vendor": d["vendor"]})

    # Risk scoring
    risk = 0
    risk += 40 * len(new_devices)
    risk += 15 * len(missing_devices)
    if mac_changes: risk += 100
    if vendor_changes: risk += 60
    if rogue_devices: risk += 120

    if risk == 0: severity="INFO"
    elif risk < 40: severity="LOW"
    elif risk < 80: severity="MEDIUM"
    elif risk < 120: severity="HIGH"
    else: severity="CRITICAL"

    summary = {
        "risk_score": risk,
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

    latest = db.query(Alert).filter(Alert.agent_id==report.agent_id)\
        .order_by(Alert.timestamp.desc()).first()

    if not latest or latest.risk_score != str(risk):
        db.add(Alert(
            id=str(uuid.uuid4()),
            agent_id=report.agent_id,
            risk_score=str(risk),
            severity=severity,
            timestamp=datetime.utcnow().isoformat()
        ))

    db.commit()
    db.close()

    return {"message":"Report stored successfully","changes":summary}

# -----------------------------
# ALERTS
# -----------------------------

@app.get("/alerts")
def alerts():
    db = SessionLocal()
    data = db.query(Alert).order_by(Alert.timestamp.desc()).all()
    db.close()
    return data

@app.get("/analytics/summary")
def summary():
    db = SessionLocal()
    result = {
        "agents": db.query(Agent).count(),
        "reports": db.query(Report).count(),
        "alerts": db.query(Alert).count()
    }
    db.close()
    return result

@app.get("/analytics/risk-trend/{hours}")
def trend(hours:int):
    db=SessionLocal()
    cutoff=datetime.utcnow()-timedelta(hours=hours)
    alerts=db.query(Alert).all()
    db.close()
    return [
        {"time":a.timestamp,"risk_score":a.risk_score}
        for a in alerts if datetime.fromisoformat(a.timestamp)>=cutoff
    ]

# -----------------------------
# LIVE SOC DASHBOARD
# -----------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
<html>
<head>
<title>HomeSecurity SOC</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body{background:#0f172a;color:white;font-family:Arial;padding:20px}
.banner{display:flex;align-items:center;gap:15px}
.logo{height:60px}
.ticker{background:#020617;padding:8px;margin:10px 0;overflow:hidden;white-space:nowrap}
.ticker span{display:inline-block;padding-left:100%;animation:ticker 15s linear infinite}
@keyframes ticker{0%{transform:translateX(0)}100%{transform:translateX(-100%)}}
.alert{padding:6px;margin:4px 0;border-radius:6px}
.CRITICAL{background:#7f1d1d}
.HIGH{background:#b45309}
.MEDIUM{background:#ca8a04}
.LOW{background:#065f46}
.INFO{background:#1e3a8a}
</style>
</head>
<body>

<div class="banner">
<img src="/static/logo.png" class="logo">
<h1>HomeSecurity SOC</h1>
</div>

<div class="ticker"><span id="ticker">Loading alerts...</span></div>

<h2>System Summary</h2>
<div id="summary"></div>

<h2>Recent Alerts</h2>
<div id="alerts"></div>

<h2>Risk Trend</h2>
<canvas id="chart"></canvas>

<script>
async function load(){
 const s=await fetch('/analytics/summary').then(r=>r.json())
 const a=await fetch('/alerts').then(r=>r.json())
 const t=await fetch('/analytics/risk-trend/24').then(r=>r.json())

 document.getElementById('summary').innerHTML=
 "Agents: "+s.agents+" | Reports: "+s.reports+" | Alerts: "+s.alerts;

 document.getElementById('alerts').innerHTML=
 a.slice(0,5).map(x=>`<div class="alert ${x.severity}">
 ${x.severity} — Risk ${x.risk_score}</div>`).join("");

 document.getElementById('ticker').innerText =
 a.slice(0,5).map(x=>`${x.severity} risk ${x.risk_score}`).join(" • ");

 new Chart(document.getElementById('chart'),{
 type:'line',
 data:{labels:t.map(x=>new Date(x.time).toLocaleTimeString()),
 datasets:[{label:'Risk',data:t.map(x=>x.risk_score)}]}
 })
}
load()
setInterval(load,10000)
</script>

</body>
</html>
"""






