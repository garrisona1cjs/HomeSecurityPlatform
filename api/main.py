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
# Dashboard Command Center Mode
# -----------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
<!DOCTYPE html>
<html>
<head>
<title>LayerSeven Command Center</title>

<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>

<style>
body {
    margin:0;
    background:#0b1220;
    color:white;
    font-family:Arial;
}

#map { height: 100vh; }

/* HUD PANEL */
#hud {
    position:absolute;
    top:10px;
    left:10px;
    z-index:999;
    background:rgba(10,15,30,0.85);
    padding:12px;
    border-radius:8px;
    font-size:13px;
}

/* legend */
.legend div {
    margin-bottom:4px;
}

/* toggle button */
#globeBtn {
    margin-top:8px;
    padding:4px 8px;
    background:#00ffff22;
    border:1px solid #00ffff55;
    color:#00ffff;
    cursor:pointer;
}
</style>
</head>
<body>


<div id="map"></div>

<div id="hud">

<b>Threat Legend</b>
<div class="legend">
<div><span style="color:#ff0033">■</span> Critical</div>
<div><span style="color:#ff6600">■</span> High</div>
<div><span style="color:#00ffff">■</span> Medium</div>
<div><span style="color:#00ccff">■</span> Low</div>
</div>

<hr>

<b>Filter Severity</b><br>
<label><input type="checkbox" checked value="critical"> Critical</label><br>
<label><input type="checkbox" checked value="high"> High</label><br>
<label><input type="checkbox" checked value="medium"> Medium</label><br>
<label><input type="checkbox" checked value="low"> Low</label>

<hr>

<button id="globeBtn">🌍 Globe Mode</button>

</div>

<script src="/static/attackMap.js"></script>

<script>
const map = L.map('map', {
    worldCopyJump:true
}).setView([20,0],2);

L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{
    attribution:'© OpenStreetMap'
}).addTo(map);

let globeMode = false;
let filters = new Set(["critical","high","medium","low"]);

// handle filter checkboxes
document.querySelectorAll('#hud input').forEach(cb=>{
    cb.addEventListener('change', e=>{
        if(e.target.checked) filters.add(e.target.value);
        else filters.delete(e.target.value);
    });
});

// globe mode toggle
document.getElementById("globeBtn").onclick = () => {

    globeMode = !globeMode;

    if(globeMode){
        map.flyTo([0,0], 1.6, { duration: 2 });
        map.dragging.disable();
    } else {
        map.flyTo([20,0], 2, { duration: 1.5 });
        map.dragging.enable();
    }
};

// cinematic camera movement
function cinematicFocus(from, to){
    map.flyToBounds([from, to], {
        padding:[120,120],
        duration:2
    });
}

// load attack paths
async function loadAttacks(){

    const paths = await fetch('/attack-paths').then(r=>r.json());

    paths.forEach(p=>{

        const severity = ["critical","high","medium","low"]
            [Math.floor(Math.random()*4)];

        if(!filters.has(severity)) return;

        drawAttackBeam(map, p.from, p.to, severity);

        if(globeMode){
            cinematicFocus(p.from, p.to);
        }
    });
}

loadAttacks();


setInterval(loadAttacks, 4000);

</script>

</body>
</html>
"""






