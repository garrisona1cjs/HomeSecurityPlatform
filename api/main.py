from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from datetime import datetime
from typing import List
import uuid, secrets, os

from sqlalchemy import create_engine, Column, String
from sqlalchemy.orm import declarative_base, sessionmaker





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
# Report → Alert Generation
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
# Attack Paths Feed
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


    for conn in active_connections:
        await conn.send_text("JOIN")

    try:
        while True:
            message = await websocket.receive_text()


            for conn in active_connections:
                await conn.send_text(message)

    except WebSocketDisconnect:
        active_connections.remove(websocket)


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
#analysts { right:10px; top:40px; }
#priority { right:10px; bottom:10px; }
</style>
</head>
<body>

<div id="globeViz"></div>

<div id="analysts" class="panel">
<b>Analysts</b>
<div id="count">0 connected</div>
</div>

<div id="priority" class="panel">
<b>Threat Level</b>
<div id="level">LOW</div>
</div>

<script>
const globe = Globe()(document.getElementById('globeViz'))
 .globeImageUrl('//unpkg.com/three-globe/example/img/earth-dark.jpg')
 .backgroundImageUrl('//unpkg.com/three-globe/example/img/night-sky.png');

globe.controls().autoRotate = true;

// WebSocket
const wsProtocol = location.protocol === "https:" ? "wss" : "ws";
const ws = new WebSocket(`${wsProtocol}://${location.host}/ws`);

let analysts = 0;
let heat = {};
let threatScore = 0;

// join/leave sync
ws.onmessage = (e) => {

    if(e.data === "JOIN") analysts++;
    else if(e.data === "LEAVE") analysts--;
    else if(e.data.startsWith("MARK:")){
        const [_,lat,lng] = e.data.split(":");
        addMarker(lat,lng);
    }

    document.getElementById("count").innerHTML =
        analysts + " connected";
};

// shared annotations
globe.onGlobeClick(({lat,lng})=>{
    ws.send(`MARK:${lat}:${lng}`);
});

function addMarker(lat,lng){
    globe.pointsData([...globe.pointsData(), {lat:lat,lng:lng,size:0.5}])
         .pointColor(()=>"#00ffff");
}

// anomaly heat detection
function heatDetect(lat,lng){
    const key = lat.toFixed(0)+lng.toFixed(0);
    heat[key] = (heat[key]||0)+1;

    if(heat[key] > 3){
        globe.pointsData([...globe.pointsData(), {lat:lat,lng:lng,size:2}])
             .pointColor(()=>"#ff0033");
    }
}

// threat feed simulation
function threatFeed(){
    const intel = [
        "Botnet signature detected",
        "Known C2 infrastructure",
        "Credential harvesting activity",
        "Malicious ASN flagged"
    ];
    if(Math.random()<0.4){
        console.log("INTEL:", intel[Math.floor(Math.random()*intel.length)]);
    }
}
setInterval(threatFeed,5000);

// triage automation
function triage(){
    if(threatScore>20) level.innerHTML="CRITICAL";
    else if(threatScore>12) level.innerHTML="HIGH";
    else if(threatScore>6) level.innerHTML="MEDIUM";
}

// red vs blue simulation
function redBlue(){
    if(Math.random()<0.3){
        threatScore += 3; // attacker success
    } else {
        threatScore -= 1; // defender mitigation
    }
    triage();
}
setInterval(redBlue,4000);

// load attacks
async function load(){
    const paths = await fetch('/attack-paths').then(r=>r.json());
    const arcs=[];
    for(const p of paths){
        heatDetect(p.from[0],p.from[1]);
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
load();
setInterval(load,3500);
</script>
</body>
</html>
"""






