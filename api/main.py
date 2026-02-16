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
# LayerSeven Mission Control
# -----------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
<!DOCTYPE html>
<html>
<head>
<title>LayerSeven Mission Control</title>

<script src="https://unpkg.com/globe.gl"></script>

<style>
body { margin:0; background:black; overflow:hidden; }

#globeViz { width:100vw; height:100vh; }

#topbar {
    position:absolute;
    top:0;
    width:100%;
    background:rgba(0,0,0,0.7);
    color:#00ffff;
    font-family:monospace;
    padding:6px;
    text-align:center;
    letter-spacing:1px;
}

#hud {
    position:absolute;
    top:36px;
    left:10px;
    color:#00ffff;
    font-family:monospace;
    background:rgba(0,10,25,0.6);
    padding:10px;
    border-radius:6px;

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

<div id="topbar">
MISSION CONTROL • GLOBAL THREAT STATUS: <span id="status">MONITORING</span>
</div>

<div id="hud">
Attacks: <span id="attackCount">0</span><br>
Campaign Risk: <span id="campaignRisk">LOW</span>
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

let totalAttacks = 0;
let originCounts = {};
let campaignScore = 0;
let feedThreats = [];

// alert queue
function pushAlert(text, level="high"){
    const q = document.getElementById("queue");
    const item = document.createElement("div");
    item.className = "queueItem " + level;
    item.innerHTML = text;
    q.appendChild(item);

    if(q.children.length > 18){
        q.removeChild(q.children[1]);
    }
}

// 🌐 simulated threat feed ingestion
function ingestThreatFeed(){

    // simulate incoming feed indicators
    if(Math.random() < 0.2){
        feedThreats.push("Known malicious IP block");
        pushAlert("🛰 Threat feed indicator received", "critical");
    }
}

setInterval(ingestThreatFeed, 7000);

// 🧠 predictive campaign modeling
function updateCampaignRisk(){

    if(campaignScore > 25){
        document.getElementById("campaignRisk").innerHTML = "HIGH";
        document.getElementById("status").innerHTML = "ELEVATED";
    }
    else if(campaignScore > 12){
        document.getElementById("campaignRisk").innerHTML = "MEDIUM";
    }
}

// 🛡 automated response playbooks
function simulateResponse(key){

    if(originCounts[key] > 8){
        pushAlert("🛡 Firewall rule deployed", "critical");
    }

    if(originCounts[key] > 12){
        pushAlert("🛡 Geo-block enabled", "critical");
    }
}

// load attacks
async function loadAttacks(){

    const paths = await fetch('/attack-paths').then(r=>r.json());

    const arcs = [];

    for (const p of paths){

        const key = p.from.toString();
        originCounts[key] = (originCounts[key] || 0) + 1;

        campaignScore += 1;

        simulateResponse(key);

        if(feedThreats.length > 0){
            pushAlert("🚨 Feed-correlated activity", "critical");
        }

        arcs.push({
            startLat: p.from[0],
            startLng: p.from[1],
            endLat: p.to[0],
            endLng: p.to[1],
            color: "#ff0033",
            stroke: 1.2
        });
    }

    globe.arcsData(arcs);

    totalAttacks += paths.length;
    document.getElementById("attackCount").innerHTML = totalAttacks;

    updateCampaignRisk();
}



loadAttacks();
setInterval(loadAttacks, 3500);
</script>
</body>
</html>
"""






