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

# =============================
# DATABASE
# =============================

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable not set")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

app = FastAPI(title="HomeSecurity Platform API", version="13.0")

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
# REGISTER
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

    return {"agent_id": agent_id, "api_key": api_key}

# =============================
# REPORT
# =============================

@app.post("/report")
def report_devices(report: DeviceReport, x_api_key: str = Header(None)):
    db = SessionLocal()
    verify_agent(db, report.agent_id, x_api_key)

    last_report = db.query(Report)\
        .filter(Report.agent_id == report.agent_id)\
        .order_by(Report.timestamp.desc())\
        .first()
    

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


    for ip, data in current_devices.items():
        if ip not in previous_devices:
            new_devices.append(data)


    for ip in previous_devices:
        if ip not in current_devices:
            missing_devices.append(ip)


    SAFE = ["Apple","Samsung","Intel","Dell","HP","Cisco","Microsoft","Google","Amazon","Raspberry"]
    rogue_devices = []

    for d in new_devices:
        vendor = d["vendor"]
        if vendor == "Unknown" or not any(s.lower() in vendor.lower() for s in SAFE):
            rogue_devices.append(d)

    risk_score = 40 * len(new_devices) + 15 * len(missing_devices)
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

    return {"risk_score": risk_score, "severity": severity}

# =============================
# NETWORK DATA
# =============================

@app.get("/network")
def network_data():
    db = SessionLocal()
    reports = db.query(Report).all()
    db.close()

    nodes = {}


    for r in reports:
        for d in json.loads(r.data):
            nodes[d["ip"]] = {
                "id": d["ip"],
                "label": d["ip"],
                "vendor": d.get("vendor","Unknown"),
                "color": "#ef4444" if d.get("vendor")=="Unknown" else "#3b82f6"
            }

    return {"nodes": list(nodes.values()), "edges": []}

# =============================
# DASHBOARD (with alert banner)
# =============================

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
<html>
<head>
<title>SOC Dashboard</title>
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<style>
body{background:#0f172a;color:white;font-family:Arial;padding:20px}
#network{height:420px;background:#111;margin-top:20px}
.panel{background:#111;padding:15px;margin-top:20px;border-radius:8px}

#alertBanner{
 position:fixed;
 top:-80px;
 left:0;
 width:100%;
 background:#dc2626;
 color:white;
 padding:18px;
 text-align:center;
 font-size:20px;
 font-weight:bold;
 transition:top 0.5s;
 z-index:9999;
}
</style>
</head>
<body>

<div id="alertBanner">⚠ CRITICAL THREAT DETECTED</div>

<h1>🛡 SOC Network Monitor</h1>

<div id="network"></div>
<div class="panel" id="details">Click a device to view intelligence.</div>

<script>
let alarmPlaying=false;
let lastThreatCount=0;

function playAlarm(){
 if(alarmPlaying) return;
 alarmPlaying=true;

 const ctx=new(window.AudioContext||window.webkitAudioContext)();
 const osc=ctx.createOscillator();
 const gain=ctx.createGain();
 osc.type="sawtooth";
 osc.frequency.setValueAtTime(880,ctx.currentTime);
 osc.connect(gain);
 gain.connect(ctx.destination);
 gain.gain.setValueAtTime(0.1,ctx.currentTime);
 osc.start();
 setTimeout(()=>{osc.stop();alarmPlaying=false;},800);
}

function showBanner(message){
 const banner=document.getElementById("alertBanner");
 banner.innerText=message;
 banner.style.top="0px";
 setTimeout(()=>banner.style.top="-80px",5000);
}

async function loadNetwork(){
 const res=await fetch('/network');
 const net=await res.json();



 const data={
  nodes:new vis.DataSet(net.nodes),
  edges:new vis.DataSet(net.edges)
 };

 const network=new vis.Network(document.getElementById('network'),data,{physics:false});

 let threats=data.nodes.get().filter(n=>n.color==="#ef4444");

 if(threats.length>lastThreatCount){
    showBanner("🚨 NEW THREAT DETECTED: "+threats[0].id);
    playAlarm();
 }

 lastThreatCount=threats.length;

 network.on("click",function(params){
   if(params.nodes.length){
     const node=data.nodes.get(params.nodes[0]);
     document.getElementById("details").innerHTML=
     "<b>IP:</b> "+node.id+"<br><b>Vendor:</b>"+node.vendor;
   }
 });

 // pulse threats
 setInterval(()=>{
  data.nodes.forEach(n=>{
   if(n.color==="#ef4444"){
     n.size=n.size===18?26:18;
   }
  });
  network.setData(data);
 },800);
}

loadNetwork();
setInterval(loadNetwork,10000);
</script>

</body>
</html>
"""






