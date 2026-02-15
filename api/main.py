from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from datetime import datetime
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

app = FastAPI(title="HomeSecurity Platform API", version="14.0.0")

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
# Dashboard with Heat Map
# -----------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
<html>
<head>
<title>HomeSecurity SOC Dashboard</title>
<style>
body {font-family: Arial; background:#0f172a; color:white; padding:20px;}
.ticker {overflow:hidden; white-space:nowrap; background:#020617; padding:8px;}
.ticker span {display:inline-block; padding-left:100%; animation:ticker 18s linear infinite;}
@keyframes ticker {0%{transform:translateX(0);}100%{transform:translateX(-100%);}}

.heatmap {display:flex; gap:10px; margin:20px 0;}
.cell {flex:1; height:50px; border-radius:6px;}

.overlay {
 position:fixed; top:0; left:0;
 width:100%; height:100%;
 background:rgba(0,0,0,0.85);
 display:none; align-items:center; justify-content:center;
 z-index:9999;
}

.alert-box {
 background:#7f1d1d;
 padding:40px;
 border-radius:12px;
 text-align:center;
 animation:pulse 1s infinite;
}

@keyframes pulse {
 0%{box-shadow:0 0 10px red;}
 50%{box-shadow:0 0 40px red;}
 100%{box-shadow:0 0 10px red;}
}


</style>
</head>
<body>

<div class="ticker"><span id="tickerText">Loading...</span></div>

<h1>🛡 SOC Threat Dashboard</h1>

<h3>Threat Heat Map</h3>
<div class="heatmap">
  <div id="low" class="cell"></div>
  <div id="medium" class="cell"></div>
  <div id="high" class="cell"></div>
  <div id="critical" class="cell"></div>
</div>

<h3>Recent Alerts</h3>
<div id="alerts"></div>

<div id="overlay" class="overlay">
  <div class="alert-box">
    <h1>🚨 INTRUSION DETECTED 🚨</h1>
    <p>Critical threat detected</p>
    <button onclick="ack()">ACKNOWLEDGE</button>
  </div>
</div>

<script>
let alarm = new Audio("https://assets.mixkit.co/sfx/preview/mixkit-alert-alarm-1005.mp3");
alarm.loop = true;
let acknowledged=false;

function ack(){
 acknowledged=true;
 document.getElementById("overlay").style.display="none";
}

async function load(){
 const alerts = await fetch('/alerts').then(r=>r.json());

 let counts={INFO:0,LOW:0,MEDIUM:0,HIGH:0,CRITICAL:0};
 alerts.forEach(a=>counts[a.severity]++);

 document.getElementById("low").style.background = counts.LOW ? "#22c55e":"#1e293b";
 document.getElementById("medium").style.background = counts.MEDIUM ? "#facc15":"#1e293b";
 document.getElementById("high").style.background = counts.HIGH ? "#fb923c":"#1e293b";
 document.getElementById("critical").style.background = counts.CRITICAL ? "#ef4444":"#1e293b";

 document.getElementById("alerts").innerHTML =
 alerts.slice(0,5).map(a =>
 `<div style="margin:6px;padding:8px;border-left:6px solid ${
   a.severity=="CRITICAL"?"red":
   a.severity=="HIGH"?"orange":
   a.severity=="MEDIUM"?"yellow":
   a.severity=="LOW"?"green":"gray"
 }">
 <b>${a.severity}</b> — Score ${a.risk_score}
 </div>`).join("");

 document.getElementById("tickerText").innerHTML =
 alerts.slice(0,10).map(a => a.severity + " alert").join(" ⚠ ");

 if(counts.CRITICAL && !acknowledged){
   document.getElementById("overlay").style.display="flex";
   alarm.play().catch(()=>{});
 } else if(!counts.CRITICAL){
   alarm.pause();
   alarm.currentTime=0;
   acknowledged=false;
 }
}

load();
setInterval(load,5000);
</script>
</body>
</html>
"""





