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
# LayerSeven Command Center Intelligence Suite
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

/* panels */
.panel {
    position:absolute;
    background:rgba(0,10,25,0.85);
    padding:10px;
    border-radius:6px;

    font-size:12px;
}

#actors { left:10px; top:40px; width:260px; }
#collab { right:10px; top:40px; width:260px; }
#metrics { left:10px; bottom:10px; width:260px; }
#executive { right:10px; bottom:10px; width:260px; }

.card {
    border:1px solid #00ffff55;
    padding:6px;
    margin-top:6px;
}

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
<b>Threat Actor Intelligence</b>
<div id="actorCards"></div>
</div>

<div id="collab" class="panel">
<b>Analyst Presence</b>
<div id="analysts"></div>
</div>

<div id="metrics" class="panel">
<b>SOC Performance</b><br>
Detections: <span id="detections">0</span><br>
Response Actions: <span id="responses">0</span><br>
Mean Response Time: <span id="mrt">0</span>s
</div>

<div id="executive" class="panel">
<b>Executive Briefing</b>
<button onclick="exportSlides()">Generate Slide Deck</button>
</div>

<script>
const globe = Globe()(document.getElementById('globeViz'))
  .globeImageUrl('//unpkg.com/three-globe/example/img/earth-dark.jpg')
  .backgroundImageUrl('//unpkg.com/three-globe/example/img/night-sky.png')
  .atmosphereColor('#00ffff')
  .atmosphereAltitude(0.25);

globe.controls().autoRotate = true;

let techniqueHeat = {};
let actorProfiles = {};
let detections = 0;
let responses = 0;

// MITRE heat overlay
function updateHeat(lat,lng){
    globe.pointsData([...globe.pointsData(), {
        lat:lat,
        lng:lng,
        size:1.5
    }])
    .pointAltitude(0.4)
    .pointColor(()=>"#ff0033");
}

// threat actor cards
function updateActorProfile(region){

    actorProfiles[region] = (actorProfiles[region] || 0) + 1;

    const cardArea = document.getElementById("actorCards");
    cardArea.innerHTML = "";

    Object.keys(actorProfiles).forEach(r=>{
        cardArea.innerHTML +=
        "<div class='card'>Region: "+r+
        "<br>Activity: "+actorProfiles[r]+
        "<br>Profile: Coordinated Campaign</div>";
    });
}

// analyst presence simulation
function updateAnalysts(){

    const names = ["Alex","Jordan","Taylor","Morgan"];
    const active = names.slice(0, Math.floor(Math.random()*names.length)+1);

    document.getElementById("analysts").innerHTML =
        active.join("<br>");
}

// SOC metrics
function updateMetrics(){
    detections += Math.floor(Math.random()*3)+1;
    responses += Math.floor(Math.random()*2);

    document.getElementById("detections").innerHTML = detections;
    document.getElementById("responses").innerHTML = responses;
    document.getElementById("mrt").innerHTML =
        Math.max(2, 10 - responses);
}

// executive slide export
function exportSlides(){

    const content = `
LayerSeven Executive Brief

Total Detections: ${detections}
Response Actions: ${responses}
Active Regions: ${Object.keys(actorProfiles).length}
SOC Efficiency Score: ${detections - responses}
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

        updateHeat(p.from[0], p.from[1]);
        updateActorProfile(region);

        detections++;

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

setInterval(updateAnalysts, 5000);
setInterval(updateMetrics, 4000);
loadAttacks();
setInterval(loadAttacks, 3500);
</script>
</body>
</html>
"""






