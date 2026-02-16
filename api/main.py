from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from datetime import datetime
from typing import List
import uuid, secrets, os, json

from sqlalchemy import create_engine, Column, String, Text
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
# Register
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
# Report (generates alerts)
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
# Alerts
# -----------------------------

@app.get("/alerts")
def alerts():
    db = SessionLocal()
    a = db.query(Alert).order_by(Alert.timestamp.desc()).all()
    db.close()
    return a

# -----------------------------
# Attack Paths (for map)
# -----------------------------
@app.get("/attack-paths")
def attack_paths():
    # simulated global attack paths → your SOC location
    return [
        {"from":[55.75,37.61], "to":[41.59,-93.62]},  # Moscow → Iowa
        {"from":[35.68,139.69], "to":[41.59,-93.62]}, # Tokyo → Iowa
        {"from":[51.50,-0.12], "to":[41.59,-93.62]},  # London → Iowa
        {"from":[-23.55,-46.63], "to":[41.59,-93.62]},# Brazil → Iowa
        {"from":[37.77,-122.41], "to":[41.59,-93.62]} # SF → Iowa
    ]

# -----------------------------
# WebSocket Collaboration Hub
# -----------------------------

active_connections = []

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)

# -----------------------------
# LayerSeven Real-Time Command Center
# -----------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
<!DOCTYPE html>
<html>
<head>
<title>LayerSeven Command Center</title>

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


#collab { right:10px; top:40px; width:260px; }
#actors { left:10px; top:40px; width:260px; }
#risk { right:10px; bottom:10px; width:260px; }
#wallboard { left:10px; bottom:10px; width:260px; }

.card { border:1px solid #00ffff55; padding:6px; margin-top:6px; }

button {
    width:100%;
    margin-top:6px;
    background:#001f33;

    border:1px solid #00ffff55;
    color:#00ffff;
    padding:4px;

}
</style>
</head>
<body>

<div id="globeViz"></div>

<div id="actors" class="panel">
<b>Threat Actor Dossiers</b>
<div id="actorCards"></div>
</div>

<div id="collab" class="panel">
<b>Live Analysts</b>
<div id="analysts"></div>
</div>

<div id="risk" class="panel">
<b>AI Threat Priority</b><br>
Top Risk Score: <span id="riskScore">0</span>
</div>

<div id="wallboard" class="panel">
<b>Wallboard Mode</b>
<button onclick="cycleView()">Cycle View</button>
<button onclick="exportSlides()">Export Executive PPT</button>
</div>

<script>
const globe = Globe()(document.getElementById('globeViz'))
  .globeImageUrl('//unpkg.com/three-globe/example/img/earth-dark.jpg');

globe.controls().autoRotate = true;

// 🌐 WebSocket collaboration
const ws = new WebSocket(`ws://${location.host}/ws`);

let analysts = [];

ws.onopen = () => {
    ws.send("join");
    analysts.push("You");
    updateAnalysts();
};

function updateAnalysts(){
    document.getElementById("analysts").innerHTML =
        analysts.join("<br>");
}

// simulate additional analysts joining
setInterval(()=>{
    const names=["Alex","Jordan","Taylor","Morgan"];
    if(Math.random() < .4){
        analysts.push(names[Math.floor(Math.random()*names.length)]);
        updateAnalysts();
    }
},6000);

// 🕵️ actor dossier intelligence
let actorProfiles = {};

function updateActor(region){

    actorProfiles[region] = (actorProfiles[region] || 0) + 1;

    const panel = document.getElementById("actorCards");
    panel.innerHTML="";

    Object.keys(actorProfiles).forEach(r=>{
        panel.innerHTML +=
        "<div class='card'>Region: "+r+
        "<br>Activity: "+actorProfiles[r]+
        "<br>Profile: Persistent Campaign</div>";
    });
}

// 🤖 AI risk prioritization
let riskScore = 0;

function updateRisk(level){
    riskScore += level;
    document.getElementById("riskScore").innerHTML = riskScore;
}

// 🖥 wallboard layout modes
let viewMode = 0;

function cycleView(){

    viewMode = (viewMode+1)%3;

    if(viewMode===0){
        globe.pointOfView({lat:0,lng:0,altitude:2});
    }
    if(viewMode===1){
        globe.pointOfView({lat:30,lng:-40,altitude:1.2});
    }
    if(viewMode===2){
        globe.pointOfView({lat:-10,lng:120,altitude:1.2});
    }
}

// 📊 PowerPoint export
function exportSlides(){

    const content = `
LayerSeven Executive Briefing

Risk Score: ${riskScore}
Active Campaign Regions: ${Object.keys(actorProfiles).length}
Active Analysts: ${analysts.length}
`;

    const blob = new Blob([content], {type:"text/plain"});
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "executive_brief.txt";
    link.click();
}

// load attacks
async function loadAttacks(){

    const paths = await fetch('/attack-paths').then(r=>r.json());

    const arcs = [];

    for(const p of paths){

        const region = p.from[0].toFixed(0)+","+p.from[1].toFixed(0);

        updateActor(region);
        updateRisk(2);

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






