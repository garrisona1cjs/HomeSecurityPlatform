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
# Globe Intelligence Command Center
# -----------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
<!DOCTYPE html>
<html>
<head>
<title>LayerSeven Globe Intelligence</title>

<script src="https://unpkg.com/globe.gl"></script>

<style>
body { margin:0; background:black; overflow:hidden; }

#globeViz { width:100vw; height:100vh; }

#hud {
    position:absolute;
    top:10px;
    left:10px;
    color:#00ffff;
    font-family:monospace;
    background:rgba(0,10,25,0.65);
    padding:10px;
    border-radius:6px;
    z-index:999;
}

#timeline {
    position:absolute;
    bottom:0;
    width:100%;
    max-height:140px;
    overflow:hidden;
    font-family:monospace;
    font-size:12px;
    color:#00ffff;
    background:rgba(0,10,25,0.85);
    padding:6px;
}

#legend {
    position:absolute;
    right:10px;
    top:10px;
    background:rgba(0,10,25,0.65);
    padding:8px;
    color:#00ffff;
    font-family:monospace;
    border-radius:6px;
}
</style>
</head>
<body>

<div id="globeViz"></div>

<div id="hud">
<b>LayerSeven Intelligence</b><br>
<span id="attackCount">Attacks: 0</span><br>
<span id="aiAlert"></span>
</div>

<div id="legend">
<b>Threat Heat</b><br>
■ Low<br>
■■ Moderate<br>
■■■ Elevated<br>
■■■■ Severe<br>
</div>

<div id="timeline"></div>

<script>
const globe = Globe()(document.getElementById('globeViz'))
  .globeImageUrl('//unpkg.com/three-globe/example/img/earth-dark.jpg')
  .backgroundImageUrl('//unpkg.com/three-globe/example/img/night-sky.png')
  .arcDashLength(0.35)
  .arcDashGap(3)
  .arcDashAnimateTime(2000)

  .atmosphereColor('#00ffff')
  .atmosphereAltitude(0.25);

globe.controls().autoRotate = true;
globe.controls().autoRotateSpeed = 0.5;

let attackHistory = [];

let originCounts = {};
let anomalyScores = {};
let totalAttacks = 0;
let playbackMode = false;

// severity thickness
const thickness = { critical:1.4, high:1.1, medium:0.8, low:0.6 };

// timeline logger
function logEvent(text){
    const panel = document.getElementById("timeline");
    const line = document.createElement("div");
    line.innerHTML = new Date().toLocaleTimeString() + " — " + text;
    panel.prepend(line);

    while(panel.children.length > 12){
        panel.removeChild(panel.lastChild);
    }
}

// 🧠 anomaly scoring
function updateAnomaly(key){
    anomalyScores[key] = (anomalyScores[key] || 0) + 1;

    if(anomalyScores[key] > 12){
        document.getElementById("aiAlert").innerHTML =
            "⚠ Anomalous traffic spike detected";
    }
}

// 🌎 geolocation label
function createLabel(lat, lng, text){
    globe.labelsData([...globe.labelsData(), {
        lat: lat,
        lng: lng,
        text: text,
        size: 1.2,
        color: "#00ffff"
    }]);
}

// 🛰 threat feed correlation (framework)
function threatFeedMatch(key){
    // placeholder: integrate live feeds later
    if(anomalyScores[key] > 15) return true;
    return false;
}

// heat glow density
function updateHotspots(){

    const points = Object.keys(originCounts).map(k=>{
        const parts = k.split(",");
        return {
            lat: parseFloat(parts[0]),
            lng: parseFloat(parts[1]),
            size: originCounts[k] * 0.35
        };
    });

    globe.pointsData(points)
         .pointAltitude(d => d.size)
         .pointColor(() => '#ff0033')
         .pointRadius(0.5);
}

// cinematic playback mode
function playbackSequence(){
    playbackMode = true;
    globe.controls().autoRotateSpeed = 0.2;

    let i = 0;

    const interval = setInterval(() => {
        if(i >= attackHistory.length){
            clearInterval(interval);
            playbackMode = false;
            globe.controls().autoRotateSpeed = 0.5;
            return;
        }

        const a = attackHistory[i];

        globe.pointOfView({
            lat: a.startLat,
            lng: a.startLng,
            altitude: 0.7
        }, 1800);

        i++;
    }, 2000);
}

// load attacks
async function loadAttacks(){

    const paths = await fetch('/attack-paths').then(r=>r.json());

    const arcs = paths.map(p => {
    


        const key = p.from.toString();
        originCounts[key] = (originCounts[key] || 0) + 1;
        updateAnomaly(key);

        const severity = ["critical","high","medium","low"]
            [Math.floor(Math.random()*4)];

        const color = "#ff0033";

        if(threatFeedMatch(key)){
            logEvent("⚠ Threat feed match detected");
        }

        createLabel(p.from[0], p.from[1], "Origin");

        logEvent("Activity from " + key);

        return {
            startLat: p.from[0],
            startLng: p.from[1],
            endLat: p.to[0],
            endLng: p.to[1],
            color: color,
            stroke: thickness[severity]
        };
    });

    attackHistory = attackHistory.concat(arcs);
    if(attackHistory.length > 80) attackHistory.shift();

    globe.arcsData(attackHistory)
         .arcStroke(d => d.stroke);

    totalAttacks += arcs.length;
    document.getElementById("attackCount").innerHTML =
        "Attacks: " + totalAttacks;

    updateHotspots();
}

// playback every 45 seconds for executive demo
setInterval(playbackSequence, 45000);

loadAttacks();
setInterval(loadAttacks, 3500);
</script>
</body>
</html>
"""






