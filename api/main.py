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
    raise RuntimeError("DATABASE_URL not set")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

app = FastAPI(title="HomeSecurity Platform API", version="16.0")

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
# Models
# -----------------------------

class Agent(Base):
    __tablename__ = "agents"
    agent_id = Column(String, primary_key=True)
    hostname = Column(String)
    ip_address = Column(String)
    api_key = Column(String)

class Report(Base):
    __tablename__ = "reports"
    id = Column(String, primary_key=True)
    agent_id = Column(String)
    data = Column(Text)
    timestamp = Column(String)

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(String, primary_key=True)
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

def verify_agent(db, agent_id: str, api_key: str):
    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent or agent.api_key != api_key:
        raise HTTPException(status_code=401, detail="Invalid agent")

# -----------------------------
# Register Agent
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

    return {"agent_id": agent_id, "api_key": api_key}

# -----------------------------
# Report Devices
# -----------------------------

@app.post("/report")
def report(report: DeviceReport, x_api_key: str = Header(None)):
    db = SessionLocal()
    verify_agent(db, report.agent_id, x_api_key)

    devices = []
    rogue = False

    for d in report.devices:
        vendor = get_vendor(d["mac"])
        if vendor == "Unknown":
            rogue = True
        devices.append({"ip": d["ip"], "mac": d["mac"], "vendor": vendor})

    db.add(Report(
        id=str(uuid.uuid4()),
        agent_id=report.agent_id,
        data=json.dumps(devices),
        timestamp=datetime.utcnow().isoformat()
    ))

    if rogue:
        db.add(Alert(
            id=str(uuid.uuid4()),
            agent_id=report.agent_id,
            risk_score="120",
            severity="CRITICAL",
            timestamp=datetime.utcnow().isoformat()
        ))

    db.commit()
    db.close()

    return {"status": "ok"}

# -----------------------------
# Agent Status API
# -----------------------------

@app.get("/agents/status")
def agent_status():
    db = SessionLocal()
    agents = db.query(Agent).all()
    results = []

    for agent in agents:
        last = (
            db.query(Report)
            .filter(Report.agent_id == agent.agent_id)
            .order_by(Report.timestamp.desc())
            .first()
        )

        status = "OFFLINE"

        if last:
            last_time = datetime.fromisoformat(last.timestamp)
            minutes = (datetime.utcnow() - last_time).total_seconds() / 60

            if minutes < 5:
                status = "ONLINE"
            elif minutes < 60:
                status = "IDLE"

        results.append({
            "id": agent.agent_id,
            "label": agent.hostname,
            "ip": agent.ip_address,
            "status": status
        })

    db.close()
    return results

# -----------------------------
# Network Map Dashboard
# -----------------------------

@app.get("/network-map", response_class=HTMLResponse)
def network_map():
    return """
<html>
<head>
<title>Network Map</title>
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<style>
body { background:#0f172a; color:white; font-family:Arial; }
#network { width:100%; height:600px; border:1px solid #1e293b; }
</style>
</head>
<body>

<h2>🌐 Live Network Map</h2>
<div id="network"></div>

<script>
async function draw(){

 const data = await fetch('/agents/status').then(r=>r.json());

 const nodes = data.map(a => ({
   id: a.id,
   label: a.label + "\\n" + a.ip,
   color:
     a.status === "ONLINE" ? "#22c55e" :
     a.status === "IDLE" ? "#facc15" :
     "#ef4444"
 }));

 const edges = data.map(a => ({
   from: "core",
   to: a.id
 }));

 nodes.push({
   id: "core",
   label: "HomeSecurity Core",
   shape: "box",
   color: "#38bdf8"
 });

 const container = document.getElementById('network');
 const network = new vis.Network(container, {
   nodes: new vis.DataSet(nodes),
   edges: new vis.DataSet(edges)
 }, {
   physics: { stabilization: false }
 });
}

draw();
setInterval(draw, 5000);
</script>

</body>
</html>
"""






