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
# LayerSeven Threat Intelligence Command Center
# -----------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
<!DOCTYPE html>
<html>
<head>
<title>LayerSeven Threat Intelligence</title>

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

#queue {
    position:absolute;
    right:10px;
    bottom:10px;
    width:280px;
    max-height:260px;
    overflow:auto;
    font-family:monospace;
    font-size:12px;

    background:rgba(0,10,25,0.85);


    padding:8px;
    color:#00ffff;

    border-radius:6px;
}

.queueItem { margin-bottom:4px; }

.critical { color:#ff0033; }
.high { color:#ff6600; }
</style>
</head>
<body>

<div id="globeViz"></div>

<div id="hud">
<b>LayerSeven Threat Intelligence</b><br>
<span id="attackCount">Attacks: 0</span><br>
<span id="aiAlert"></span>
</div>

<div id="queue"><b>Alert Queue</b><br></div>

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


let attackHistory = [];

let originCounts = {};

let totalAttacks = 0;
let campaignClusters = {};
let blockedOrigins = {};

// severity thickness
const thickness = { critical:1.5, high:1.2, medium:0.8, low:0.6 };

// 🔥 Alert queue
function pushAlert(text, level="high"){

    const queue = document.getElementById("queue");
    const item = document.createElement("div");
    item.className = "queueItem " + level;
    item.innerHTML = text;
    queue.appendChild(item);

    if(queue.children.length > 18){
        queue.removeChild(queue.children[1]);
    }
}

// 🌍 country flag (simple region logic)
function getFlag(lat){
    if(lat > 40 && lat < 70) return "🇷🇺";
    if(lat > 20 && lat < 40) return "🇨🇳";
    if(lat < -10 && lat > -40) return "🇧🇷";
    return "🌐";
}

// 🛰 AbuseIPDB LOOKUP (LIVE READY)
async function checkAbuseIP(ip){

    // 🔐 Replace with real API later:
    // const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, {
    //   headers: { Key: "YOUR_API_KEY", Accept: "application/json" }
    // });

    // demo logic
    if(Math.random() < 0.15){
        return true;
    }
    return false;
}

// 🔥 heat intensity rings
function drawHeatRing(lat, lng, intensity){

    globe.ringsData([...globe.ringsData(), {
        lat: lat,
        lng: lng,
        maxR: intensity * 2,
        propagationSpeed: 2,
        repeatPeriod: 700
    }]);
}

// 🧠 campaign clustering
function updateCampaign(key){
    campaignClusters[key] = (campaignClusters[key] || 0) + 1;

    if(campaignClusters[key] === 6){
        pushAlert("⚠ Coordinated campaign emerging", "critical");
    }
}

// 🛡 mitigation simulation
function simulateMitigation(key){

    if(originCounts[key] > 12 && !blockedOrigins[key]){
        blockedOrigins[key] = true;
        pushAlert("🛡 Mitigation simulated: origin blocked", "critical");
    }
}

// 🖥 multi-screen mode (auto view cycling)
let viewMode = 0;
setInterval(()=>{
    viewMode = (viewMode + 1) % 3;

    if(viewMode === 0){
        globe.controls().autoRotateSpeed = 0.5;
    }
    if(viewMode === 1){
        globe.pointOfView({ lat:0, lng:0, altitude:1.8 }, 2000);
    }
    if(viewMode === 2){
        globe.pointOfView({ lat:30, lng:-40, altitude:1.2 }, 2000);
    }

}, 30000);

// load attacks
async function loadAttacks(){

    const paths = await fetch('/attack-paths').then(r=>r.json());

    for (const p of paths){

        const key = p.from.toString();
        originCounts[key] = (originCounts[key] || 0) + 1;

        updateCampaign(key);
        simulateMitigation(key);

        const flagged = await checkAbuseIP(key);

        if(flagged){
            pushAlert("🚨 AbuseIPDB flagged origin", "critical");
        }

        const flag = getFlag(p.from[0]);

        pushAlert(flag + " Activity detected");

        // heat ring for persistent threats
        if(originCounts[key] > 4){
            drawHeatRing(p.from[0], p.from[1], originCounts[key]);
        }

        const severity = ["critical","high","medium","low"]
            [Math.floor(Math.random()*4)];

        attackHistory.push({
            startLat: p.from[0],
            startLng: p.from[1],
            endLat: p.to[0],
            endLng: p.to[1],
            color: flagged ? "#ff0033" : "#ff6600",
            stroke: thickness[severity]
        });
    }
    


    if(attackHistory.length > 80) attackHistory.shift();

    globe.arcsData(attackHistory)
         .arcStroke(d => d.stroke);

    totalAttacks += paths.length;
    document.getElementById("attackCount").innerHTML =
        "Attacks: " + totalAttacks;


}



loadAttacks();
setInterval(loadAttacks, 3500);
</script>
</body>
</html>
"""






