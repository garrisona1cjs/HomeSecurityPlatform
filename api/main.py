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

app = FastAPI(title="HomeSecurity Platform API", version="17.0")

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

SAFE_VENDORS = ["Apple","Samsung","Intel","Dell","HP","Cisco","Microsoft","Google","Amazon","Raspberry"]

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

    for d in report.devices:
        vendor = get_vendor(d["mac"])

        rogue = (
            vendor == "Unknown" or
            not any(v.lower() in vendor.lower() for v in SAFE_VENDORS)
        )

        devices.append({
            "ip": d["ip"],
            "mac": d["mac"],
            "vendor": vendor,
            "rogue": rogue
        })

    db.add(Report(
        id=str(uuid.uuid4()),
        agent_id=report.agent_id,
        data=json.dumps(devices),
        timestamp=datetime.utcnow().isoformat()
    ))

    db.commit()
    db.close()

    return {"status": "ok"}

# -----------------------------
# Network Map Data API
# -----------------------------

@app.get("/network-data")
def network_data():
    db = SessionLocal()

    agents = db.query(Agent).all()

    nodes = []
    edges = []

    nodes.append({
        "id": "core",
        "label": "HomeSecurity Core",
        "shape": "box",
        "color": "#38bdf8"
    })

    for agent in agents:

        # determine status
        last = (
            db.query(Report)
            .filter(Report.agent_id == agent.agent_id)
            .order_by(Report.timestamp.desc())
            .first()
        )

        status = "OFFLINE"
        if last:
            last_time = datetime.fromisoformat(last.timestamp)
            minutes = (datetime.utcnow() - last_time).total_seconds()/60
            if minutes < 5:
                status = "ONLINE"
            elif minutes < 60:
                status = "IDLE"

        color = "#22c55e" if status=="ONLINE" else "#facc15" if status=="IDLE" else "#ef4444"

        nodes.append({
            "id": agent.agent_id,
            "label": agent.hostname + "\\n" + agent.ip_address,
            "color": color
        })

        edges.append({"from": "core", "to": agent.agent_id})

        if last:
            devices = json.loads(last.data)

            for dev in devices:
                dev_id = agent.agent_id + "_" + dev["ip"]

                nodes.append({
                    "id": dev_id,
                    "label": dev["ip"],
                    "title": f'{dev["vendor"]}',
                    "color": "#ef4444" if dev["rogue"] else "#60a5fa",
                    "shape": "dot",
                    "size": 12
                })

                edges.append({"from": agent.agent_id, "to": dev_id})

    db.close()
    return {"nodes": nodes, "edges": edges}

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
#network { width:100%; height:650px; border:1px solid #1e293b; }
</style>
</head>
<body>

<h2>🌐 Live Network Topology</h2>
<div id="network"></div>

<script>
async function draw(){

 const res = await fetch('/network-data');
 const data = await res.json();

 const container = document.getElementById('network');

 new vis.Network(container, data, {
   physics: { stabilization: false },
   interaction: { hover: true }
 });
}

draw();
setInterval(draw, 5000);
</script>

</body>
</html>
"""






