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

# =============================
# DATABASE
# =============================

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable not set")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

app = FastAPI(title="HomeSecurity Platform API", version="10.0")

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
    agent_id = Column(String, primary_key=True)
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
    return agent

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
        "api_key": api_key
    }

# =============================
# REPORT DEVICES
# =============================

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

    # Rogue device detection
    SAFE = ["Apple","Samsung","Intel","Dell","HP","Cisco","Microsoft","Google","Amazon","Raspberry"]
    rogue_devices = []

    for d in new_devices:
        vendor = d["vendor"]
        if vendor == "Unknown":
            rogue_devices.append({"ip": d["ip"], "reason": "Unknown vendor"})
        elif not any(s.lower() in vendor.lower() for s in SAFE):
            rogue_devices.append({"ip": d["ip"], "vendor": vendor})

    # Risk scoring
    risk_score = 0
    risk_score += 40 * len(new_devices)
    risk_score += 15 * len(missing_devices)

    if mac_changes:
        risk_score += 100
    if vendor_changes:
        risk_score += 60
    if rogue_devices:
        risk_score += 120

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

    return {"message": "Report stored", "changes": summary}

# =============================
# ALERTS API
# =============================

@app.get("/alerts")
def get_alerts():
    db = SessionLocal()
    alerts = db.query(Alert).order_by(Alert.timestamp.desc()).all()
    db.close()
    return alerts

# =============================
# RISK TREND
# =============================

@app.get("/analytics/risk-trend/{hours}")
def risk_trend(hours: int):
    db = SessionLocal()
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    alerts = db.query(Alert).all()

    trend = [
        {"time": a.timestamp, "risk_score": int(a.risk_score)}
        for a in alerts
        if datetime.fromisoformat(a.timestamp) >= cutoff
    ]

    db.close()
    return trend

# =============================
# NETWORK MAP DATA
# =============================

@app.get("/network")
def network_data():
    db = SessionLocal()
    reports = db.query(Report).all()
    db.close()

    nodes = {}
    edges = []

    for r in reports:
        devices = json.loads(r.data)
        for d in devices:
            ip = d["ip"]
            vendor = d.get("vendor", "Unknown")

            if ip not in nodes:
                nodes[ip] = {
                    "id": ip,
                    "label": ip,
                    "title": vendor,
                    "color": "#ef4444" if vendor == "Unknown" else "#3b82f6"
                }

    return {"nodes": list(nodes.values()), "edges": edges}

# =============================
# DASHBOARD
# =============================

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
<html>
<head>
<title>HomeSecurity SOC</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<style>
body {background:#0f172a;color:white;font-family:Arial;padding:20px}
.ticker {overflow:hidden;white-space:nowrap;background:#111;padding:10px;margin-bottom:20px}
.ticker span {display:inline-block;padding-left:100%;animation:ticker 20s linear infinite}
@keyframes ticker {0%{transform:translateX(0)}100%{transform:translateX(-100%)}}
</style>
</head>
<body>

<h1>🛡 HomeSecurity SOC Dashboard</h1>

<div class="ticker"><span id="ticker">Loading alerts...</span></div>

<h2>Recent Alerts</h2>
<div id="alerts"></div>

<h2>Risk Trend</h2>
<canvas id="riskChart" width="600" height="200"></canvas>

<h2>Network Map</h2>
<div id="network" style="height:400px;background:#111;"></div>

<script>
function severityColor(s){
 if(s==="INFO") return "#22c55e";
 if(s==="LOW") return "#3b82f6";
 if(s==="MEDIUM") return "#eab308";
 if(s==="HIGH") return "#f97316";
 if(s==="CRITICAL") return "#ef4444";
 return "white";
}

async function load(){
 const alerts=await fetch('/alerts').then(r=>r.json());
 const trend=await fetch('/analytics/risk-trend/24').then(r=>r.json());
 const network=await fetch('/network').then(r=>r.json());

 document.getElementById("ticker").innerHTML =
   alerts.slice(0,10).map(a =>
     `${a.severity} threat detected (score ${a.risk_score})`
   ).join(" ⚠️ ");

 document.getElementById("alerts").innerHTML =
 alerts.slice(0,5).map(a =>
 `<div style="margin:6px;padding:8px;border-left:6px solid ${severityColor(a.severity)};
 background:${severityColor(a.severity)}20;">
 <b>${a.severity}</b> — Score ${a.risk_score}
 </div>`).join("");

 new Chart(document.getElementById('riskChart'),{
  type:'line',
  data:{labels:trend.map(t=>new Date(t.time).toLocaleTimeString()),
  datasets:[{label:'Risk',data:trend.map(t=>t.risk_score),tension:.3}]}
 });

 const container=document.getElementById('network');
 const data={nodes:new vis.DataSet(network.nodes),edges:new vis.DataSet(network.edges)};
 const net=new vis.Network(container,data,{physics:false});

 setInterval(()=>{
  data.nodes.forEach(n=>{
    if(n.color==="#ef4444"){n.size=n.size===18?26:18;}
  });
  net.setData(data);
 },800);
}

load();
setInterval(load,10000);
</script>

</body>
</html>
"""






