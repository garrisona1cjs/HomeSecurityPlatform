from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from datetime import datetime
from typing import List
import uuid, secrets, os

from sqlalchemy import create_engine, Column, String
from sqlalchemy.orm import declarative_base, sessionmaker

from mac_vendor_lookup import MacLookup



# -----------------------------
# Database
# -----------------------------


DATABASE_URL = os.getenv("DATABASE_URL")



engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

app = FastAPI(title="LayerSeven Security Platform")






app.mount("/static", StaticFiles(directory="static"), name="static")

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

def verify_agent(db, agent_id, api_key):
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
# Device Report → Alerts
# -----------------------------

@app.post("/report")
def report_devices(report: DeviceReport, x_api_key: str = Header(None)):
    db = SessionLocal()
    verify_agent(db, report.agent_id, x_api_key)

    risk = len(report.devices) * 40
    severity = "LOW"
    if risk > 80: severity = "HIGH"
    if risk > 120: severity = "CRITICAL"

    db.add(Alert(
        id=str(uuid.uuid4()),
        agent_id=report.agent_id,
        risk_score=str(risk),
        severity=severity,
        timestamp=datetime.utcnow().isoformat()
    ))

    db.commit()
    db.close()

    return {"risk_score": risk, "severity": severity}

# -----------------------------
# Alerts Endpoint
# -----------------------------

@app.get("/alerts")
def alerts():
    db = SessionLocal()
    results = db.query(Alert).order_by(Alert.timestamp.desc()).all()
    db.close()
    return results

# -----------------------------
# Attack Paths (SOC Map Feed)
# -----------------------------

@app.get("/attack-paths")
def attack_paths():

    return [
        {"from":[55.75,37.61], "to":[41.59,-93.62]},
        {"from":[35.68,139.69], "to":[41.59,-93.62]},
        {"from":[51.50,-0.12], "to":[41.59,-93.62]},
        {"from":[-23.55,-46.63], "to":[41.59,-93.62]},
        {"from":[37.77,-122.41], "to":[41.59,-93.62]}
    ]

# -----------------------------
# 🌐 Real-Time Collaboration Hub
# -----------------------------

active_connections = set()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.add(websocket)

    # notify all clients someone joined
    for conn in active_connections:
        await conn.send_text("JOIN")

    try:
        while True:
            message = await websocket.receive_text()

            # broadcast messages (annotations etc.)
            for conn in active_connections:
                await conn.send_text(message)

    except WebSocketDisconnect:
        active_connections.remove(websocket)

        # notify clients someone left
        for conn in active_connections:
            await conn.send_text("LEAVE")

# -----------------------------
# SOC Dashboard
# -----------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
<!DOCTYPE html>
<html>
<head>
<title>LayerSeven SOC Command</title>
<script src="https://unpkg.com/globe.gl"></script>

<style>
body { margin:0; background:black; color:#00ffff; font-family:monospace; overflow:hidden;}

#globeViz { width:100vw; height:100vh; }


.panel {
 position:absolute;
 background:rgba(0,10,25,0.85);
 padding:10px;
 border-radius:6px;
 font-size:12px;
}
#analysts { right:10px; top:40px; width:200px; }
#risk { right:10px; bottom:10px; width:200px; }
</style>
</head>
<body>

<div id="globeViz"></div>

<div id="analysts" class="panel">
<b>Live Analysts</b>
<div id="analystList">0 connected</div>
</div>

<div id="risk" class="panel">
<b>Threat Priority</b><br>
Level: <span id="priority">LOW</span>
</div>

<script>
const globe = Globe()(document.getElementById('globeViz'))
 .globeImageUrl('//unpkg.com/three-globe/example/img/earth-dark.jpg')
 .backgroundImageUrl('//unpkg.com/three-globe/example/img/night-sky.png');

globe.controls().autoRotate = true;

// WebSocket (Render-safe)
const wsProtocol = location.protocol === "https:" ? "wss" : "ws";
const ws = new WebSocket(`${wsProtocol}://${location.host}/ws`);

let analysts = 0;
let alertScore = 0;

// join/leave sync
ws.onmessage = (event) => {

    if(event.data === "JOIN") analysts++;
    if(event.data === "LEAVE") analysts = Math.max(0, analysts - 1);

    document.getElementById("analystList").innerHTML =
        analysts + " connected";
};

// click globe to share markers
globe.onGlobeClick(({lat,lng})=>{
    ws.send(`MARK:${lat}:${lng}`);
});

// anomaly detection & triage
function triage(score){
    if(score > 20) priority.innerHTML = "CRITICAL";
    else if(score > 10) priority.innerHTML = "HIGH";
    else if(score > 5) priority.innerHTML = "MEDIUM";
}

// load attacks
async function loadAttacks(){

    const paths = await fetch('/attack-paths').then(r=>r.json());

    const arcs = [];

    for(const p of paths){
        alertScore += 2;
        triage(alertScore);

        arcs.push({
            startLat:p.from[0],
            startLng:p.from[1],
            endLat:p.to[0],
            endLng:p.to[1],
            color:"#ff0033",
            stroke:1.2
        });
        

    }

    globe.arcsData(arcs);



}



loadAttacks();
setInterval(loadAttacks, 3500);
</script>
</body>
</html>
"""






