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
</style>
</head>
<body>

<div id="globeViz"></div>

<div id="hud">
<b>LayerSeven Globe Intelligence</b><br>
<span id="attackCount">Attacks: 0</span><br>
<span id="aiAlert"></span>
</div>

<script>
const globe = Globe()(document.getElementById('globeViz'))
  .globeImageUrl('//unpkg.com/three-globe/example/img/earth-dark.jpg')
  .backgroundImageUrl('//unpkg.com/three-globe/example/img/night-sky.png')
  .arcDashLength(0.35)
  .arcDashGap(3)
  .arcDashAnimateTime(2000)
  .arcStroke(0.6)
  .atmosphereColor('#00ffff')
  .atmosphereAltitude(0.25);

globe.controls().autoRotate = true;
globe.controls().autoRotateSpeed = 0.5;

let attackHistory = [];
let totalAttacks = 0;
let originCounts = {};
let originTimeline = {};
let escalationTracker = {};

// 🎥 camera control
let lastCameraMove = 0;
const cameraCooldown = 5000;

// severity colors
const colors = {
    critical: "#ff0033",
    high: "#ff6600",
    medium: "#00ffff",
    low: "#00ccff"
};

// simulate severity
function randomSeverity(){
    const s = ["critical","high","medium","low"];
    return s[Math.floor(Math.random()*s.length)];
}

// 🤖 baseline pattern detection
function detectPatterns(){

    let text = "";

    if(attackHistory.length > 25){
        text += "⚠ Burst activity detected<br>";
    }

    Object.keys(originCounts).forEach(k=>{
        if(originCounts[k] > 6){
            text += "⚠ Coordinated region activity<br>";
        }
    });

    document.getElementById("aiAlert").innerHTML = text;
}

// 🧠 predictive threat behavior detection
function predictiveAnalysis(arcs){

    let warnings = [];

    arcs.forEach(a => {

        const key = a.startLat + "," + a.startLng;

        if (!originTimeline[key]) originTimeline[key] = [];
        originTimeline[key].push(Date.now());

        if (originTimeline[key].length > 20)
            originTimeline[key].shift();

        // reconnaissance detection
        if (originTimeline[key].length >= 6) {
            const span = originTimeline[key].slice(-6);
            if (span[5] - span[0] < 12000) {
                warnings.push("🔎 Recon activity detected");
            }
        }

        // escalation detection
        if (!escalationTracker[key]) escalationTracker[key] = 0;
        escalationTracker[key]++;

        if (escalationTracker[key] === 8) {
            warnings.push("📈 Escalating probe intensity");
        }

        // distributed staging detection
        if (Object.keys(originCounts).length > 5 &&
            attackHistory.length > 20) {
            warnings.push("⚠ Coordinated staging activity");
        }

    });

    return [...new Set(warnings)];
}

// 🎯 focus on critical threats
function focusCritical(arcs){

    const now = Date.now();
    if (now - lastCameraMove < cameraCooldown) return;

    const critical = arcs.find(a => a.severity === "critical");
    if(!critical) return;

    // zoom to threat
    globe.pointOfView({
        lat: critical.startLat,
        lng: critical.startLng,
        altitude: 0.6
    }, 2200);

    lastCameraMove = now;

    // return to global view
    setTimeout(() => {
        globe.pointOfView({
            lat: 20,
            lng: 0,
            altitude: 2.2
        }, 2000);
    }, 4500);
}

// 🔥 hotspot density glow
function updateHotspots(){

    const points = Object.keys(originCounts).map(k=>{
        const parts = k.split(",");
        return {
            lat: parseFloat(parts[0]),
            lng: parseFloat(parts[1]),
            size: originCounts[k] * 0.3
        };
    });

    globe.pointsData(points)
         .pointAltitude(d => d.size)
         .pointColor(() => '#ff0033')
         .pointRadius(0.5);
}

// load attacks & timeline playback
async function loadAttacks(){

    const paths = await fetch('/attack-paths').then(r=>r.json());

    const arcs = paths.map(p => {

        const severity = randomSeverity();

        const key = p.from.toString();
        originCounts[key] = (originCounts[key] || 0) + 1;

        return {
            startLat: p.from[0],
            startLng: p.from[1],
            endLat: p.to[0],
            endLng: p.to[1],
            color: colors[severity],
            severity: severity
        };
    });

    attackHistory = attackHistory.concat(arcs);
    if(attackHistory.length > 80) attackHistory.shift();

    globe.arcsData(attackHistory);

    totalAttacks += arcs.length;
    document.getElementById("attackCount").innerHTML =
        "Attacks: " + totalAttacks;

    detectPatterns();
    updateHotspots();
    focusCritical(arcs);

    const predictiveWarnings = predictiveAnalysis(arcs);

    if (predictiveWarnings.length > 0) {
        document.getElementById("aiAlert").innerHTML =
            predictiveWarnings.join("<br>");
    }
}

loadAttacks();
setInterval(loadAttacks, 3500);
</script>
</body>
</html>
"""






