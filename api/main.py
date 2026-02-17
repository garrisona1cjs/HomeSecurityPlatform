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
# Agent Registration
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
# Device Report → Alert Generation
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
# Alerts API
# -----------------------------

@app.get("/alerts")
def get_alerts():
    db = SessionLocal()
    alerts = db.query(Alert).order_by(Alert.timestamp.desc()).all()
    db.close()
    return alerts

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

connections = set()

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    connections.add(ws)

    # notify clients
    for c in connections:
        await c.send_text("JOIN")

    try:
        while True:
            msg = await ws.receive_text()
            for c in connections:
                await c.send_text(msg)
    except WebSocketDisconnect:
        connections.remove(ws)
        for c in connections:
            await c.send_text("LEAVE")

# -----------------------------
# SOC Dashboard
# -----------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
<!DOCTYPE html>
<html>
<head>
<title>LayerSeven Cyber Operations Simulator</title>
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
#status { left:10px; top:40px; }
#controls { left:10px; bottom:10px; }
</style>
</head>
<body>

<div id="globeViz"></div>

<div id="status" class="panel">
<b>Threat Level:</b> <span id="level">LOW</span><br>
<b>Analysts:</b> <span id="users">0</span>
</div>

<div id="controls" class="panel">
<button onclick="toggleTraining()">Training Mode</button>
<button onclick="replayTimeline()">Replay Campaign</button>
</div>

<script>
const globe = Globe()(document.getElementById('globeViz'))
.globeImageUrl('//unpkg.com/three-globe/example/img/earth-dark.jpg')
.backgroundImageUrl('//unpkg.com/three-globe/example/img/night-sky.png');

globe.controls().autoRotate = true;

// WebSocket (Render-safe)
const wsProtocol = location.protocol === "https:" ? "wss" : "ws";
const ws = new WebSocket(`${wsProtocol}://${location.host}/ws`);

let users = 0;
let threatScore = 0;
let history = [];
let trainingMode = false;


// analyst sync
ws.onmessage = e => {
    if(e.data==="JOIN") users++;
    else if(e.data==="LEAVE") users--;
    

    users = Math.max(0, users);
    document.getElementById("users").innerHTML = users;
};

// shared annotations
globe.onGlobeClick(({lat,lng})=>{
    ws.send(`MARK:${lat}:${lng}`);
});

// threat level
function updateThreat(){
    if(threatScore>25) level.innerHTML="CRITICAL";
    else if(threatScore>15) level.innerHTML="HIGH";
    else if(threatScore>8) level.innerHTML="MEDIUM";
}

// prediction arc
function predictNext(origin){
    return {
        startLat: origin[0],
        startLng: origin[1],
        endLat: origin[0] + (Math.random()*20-10),
        endLng: origin[1] + (Math.random()*20-10),
        color:"#ff00ff"
    };

}

// cyber battle simulation
function cyberBattle(){
    if(Math.random()<0.6) threatScore += 2;
    else threatScore -= 1;
    updateThreat();
}
setInterval(cyberBattle, 4000);

// replay
function replayTimeline(){
    let i=0;
    const r=setInterval(()=>{
        if(i>=history.length){clearInterval(r);return;}
        globe.pointOfView(history[i],1200);
        i++;
    },1500);
}

// toggle training
function toggleTraining(){
    trainingMode=!trainingMode;
}

// load attacks
async function load(){
    const paths = await fetch('/attack-paths').then(r=>r.json());
    const arcs=[];

    for(const p of paths){


        history.push({lat:p.from[0],lng:p.from[1],altitude:1});
        threatScore += trainingMode ? 3 : 2;

        arcs.push({
            startLat:p.from[0],
            startLng:p.from[1],
            endLat:p.to[0],
            endLng:p.to[1],
            color:"#ff0033",
            stroke:1.2
        });

        
        arcs.push(predictNext(p.from));
    }

    globe.arcsData(arcs);
    updateThreat();
}

load();
setInterval(load,3500);
</script>
</body>
</html>
"""






