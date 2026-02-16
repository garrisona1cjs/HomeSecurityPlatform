from fastapi import FastAPI, Header, HTTPException
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
# LayerSeven SOC Operations Console
# -----------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
<!DOCTYPE html>
<html>
<head>
<title>LayerSeven SOC Operations Console</title>

<script src="https://unpkg.com/globe.gl"></script>

<style>
body { margin:0; background:black; overflow:hidden; font-family:monospace; }

#globeViz { width:100vw; height:100vh; }

#topbar {
    position:absolute;
    top:0;
    width:100%;
    text-align:center;

    color:#00ffff;
    background:rgba(0,0,0,0.7);

    padding:6px;

}

#panel {
    position:absolute;

    left:10px;
    top:40px;
    background:rgba(0,10,25,0.75);
    padding:10px;
    border-radius:6px;
    color:#00ffff;
}

#timeline {
    position:absolute;
    bottom:0;
    width:100%;
    max-height:160px;
    overflow:auto;
    background:rgba(0,10,25,0.9);
    color:#00ffff;
    padding:6px;
    font-size:12px;
}

#casePanel {
    position:absolute;
    right:10px;
    top:40px;
    width:260px;
    background:rgba(0,10,25,0.75);
    padding:10px;
    border-radius:6px;
    color:#00ffff;

    font-size:12px;
}

button {

    width:100%;
    margin-top:6px;
    background:#001f33;

    border:1px solid #00ffff55;
    color:#00ffff;
    padding:4px;
    cursor:pointer;
}
</style>
</head>
<body>

<div id="globeViz"></div>

<div id="topbar">
SOC OPERATIONS CONSOLE • STATUS: <span id="status">MONITORING</span>
</div>

<div id="panel">
Attacks: <span id="attackCount">0</span><br>
Active Case: <span id="caseStatus">None</span><br>
Threat Technique: <span id="mitre">N/A</span>
</div>

<div id="casePanel">
<b>Case Management</b><br>
Stage: <span id="stage">Monitoring</span><br><br>
<button onclick="advanceCase()">Advance Case Stage</button>
<button onclick="replayCampaign()">Replay Campaign</button>
<button onclick="exportBrief()">Export Executive Brief</button>
</div>

<div id="timeline"></div>

<script>
const globe = Globe()(document.getElementById('globeViz'))
  .globeImageUrl('//unpkg.com/three-globe/example/img/earth-dark.jpg')
  .backgroundImageUrl('//unpkg.com/three-globe/example/img/night-sky.png');

globe.controls().autoRotate = true;

let attackHistory = [];
let totalAttacks = 0;
let caseStage = 0;
let timelineEvents = [];

const stages = ["Monitoring","Investigation","Containment","Eradication","Recovery"];

const mitreTechniques = [
    "T1595 Active Scanning",
    "T1110 Brute Force",
    "T1046 Network Discovery",
    "T1078 Valid Accounts",
    "T1021 Remote Services"
];

// timeline builder
function logEvent(text){
    timelineEvents.push(text);

    const t = document.getElementById("timeline");
    const line = document.createElement("div");
    line.innerHTML = new Date().toLocaleTimeString() + " — " + text;
    t.prepend(line);

    while(t.children.length > 20){
        t.removeChild(t.lastChild);
    }
}

// MITRE mapping
function mapTechnique(){
    const technique = mitreTechniques[
        Math.floor(Math.random()*mitreTechniques.length)
    ];

    document.getElementById("mitre").innerHTML = technique;
    logEvent("MITRE technique observed: " + technique);
}

// case workflow
function advanceCase(){
    caseStage = (caseStage + 1) % stages.length;
    document.getElementById("stage").innerHTML = stages[caseStage];
    document.getElementById("status").innerHTML = stages[caseStage].toUpperCase();
}

// campaign replay
function replayCampaign(){

    let i = 0;

    const replay = setInterval(() => {

        if(i >= attackHistory.length){
            clearInterval(replay);
            return;
        }

        const a = attackHistory[i];

        globe.pointOfView({
            lat: a.startLat,
            lng: a.startLng,
            altitude: 0.8
        }, 1200);

        i++;

    }, 1400);
}

// executive briefing export
function exportBrief(){

    const report = `
LayerSeven Executive Intelligence Brief

Total Attacks: ${totalAttacks}
Case Stage: ${stages[caseStage]}
Recent Technique: ${document.getElementById("mitre").innerText}
Events Logged: ${timelineEvents.length}
`;

    const blob = new Blob([report], {type:"text/plain"});
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
    


    

        arcs.push({
            startLat: p.from[0],
            startLng: p.from[1],
            endLat: p.to[0],
            endLng: p.to[1],
            color:"#ff0033",
            stroke:1.2
        });

        attackHistory.push({
            startLat:p.from[0],
            startLng:p.from[1]
        });

        mapTechnique();
        logEvent("Attack detected from origin");
    }

    globe.arcsData(arcs);

    totalAttacks += paths.length;
    document.getElementById("attackCount").innerHTML = totalAttacks;



}

loadAttacks();
setInterval(loadAttacks, 3500);
</script>
</body>
</html>
"""






