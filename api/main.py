from fastapi import FastAPI, Header, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from datetime import datetime
from typing import List
import uuid
import secrets
import os
import random
import asyncio
import geoip2.database

from sqlalchemy import create_engine, Column, String, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

# =========================================================
# GEOIP CONFIG
# =========================================================

GEOIP_DB = os.getenv("GEOIP_DB", "geoip/GeoLite2-City.mmdb")

def geo_lookup_ip(ip):
    try:
        with geoip2.database.Reader(GEOIP_DB) as reader:
            r = reader.city(ip)

            city = r.city.name or ""
            country = r.country.name or ""
            lat = r.location.latitude
            lon = r.location.longitude
            code = r.country.iso_code or ""

            label = f"{city}, {country}".strip(", ")

            return (label, lat, lon, code)

    except:
        return ("Unknown", 0, 0, "")

# =========================================================
# DATABASE CONFIG
# =========================================================

DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# =========================================================
# FASTAPI APP
# =========================================================


app = FastAPI(title="LayerSeven Security Platform")






app.mount("/static", StaticFiles(directory="static"), name="static")

# =========================================================
# DATABASE MODEL
# =========================================================

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True)
    agent_id = Column(String)
    risk_score = Column(String)
    severity = Column(String)
    technique = Column(String)
    timestamp = Column(String)


    origin_label = Column(String)
    latitude = Column(String)
    longitude = Column(String)
    country_code = Column(String)
    shockwave = Column(String)

# =========================================================
# SAFE SCHEMA UPDATE
# =========================================================

inspector = inspect(engine)

if "alerts" in inspector.get_table_names():
    existing = [c["name"] for c in inspector.get_columns("alerts")]

    with engine.connect() as conn:
        if "origin_label" not in existing:
            conn.execute(text("ALTER TABLE alerts ADD COLUMN origin_label VARCHAR"))
        if "latitude" not in existing:
            conn.execute(text("ALTER TABLE alerts ADD COLUMN latitude VARCHAR"))
        if "longitude" not in existing:
            conn.execute(text("ALTER TABLE alerts ADD COLUMN longitude VARCHAR"))
        if "country_code" not in existing:
            conn.execute(text("ALTER TABLE alerts ADD COLUMN country_code VARCHAR"))
        if "shockwave" not in existing:
            conn.execute(text("ALTER TABLE alerts ADD COLUMN shockwave VARCHAR"))

Base.metadata.create_all(bind=engine)

# =========================================================
# DATA SCHEMAS
# =========================================================

class AgentRegistration(BaseModel):
    hostname: str
    ip_address: str

class DeviceReport(BaseModel):
    agent_id: str
    devices: List[dict]

# =========================================================
# MITRE TECHNIQUES
# =========================================================

techniques = [
    "T1110 Brute Force",
    "T1078 Valid Accounts",
    "T1046 Network Scannin",
    "T1059 Command Exec",
    "T1566 Phishing"
]

# =========================================================
# WEBSOCKET HUB
# =========================================================

connections = set()

async def broadcast(payload):
    dead = []
    for ws in connections:
        try:
            await ws.send_json(payload)
        except:
            dead.append(ws)
    for ws in dead:
        connections.remove(ws)

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    connections.add(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        connections.remove(ws)


# =========================================================
# API ROUTES
# =========================================================

@app.post("/register")
def register(agent: AgentRegistration):
    return {
        "agent_id": str(uuid.uuid4()),
        "api_key": secrets.token_hex(16)
    }

@app.post("/report")
async def report_devices(report: DeviceReport, x_api_key: str = Header(None)):

    db = SessionLocal()


    risk = len(report.devices) * 40

    if risk >= 120:
        severity = "CRITICAL"
    elif risk >= 80:
        severity = "HIGH"
    elif risk >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"


    ip_addr = report.devices[0].get("ip", "8.8.8.8")

    origin_label, lat, lon, country = geo_lookup_ip(ip_addr)

    technique = random.choice(techniques)
    shockwave_flag = "true" if severity == "CRITICAL" else "false"


    alert = Alert(
        id=str(uuid.uuid4()),
        agent_id=report.agent_id,
        risk_score=str(risk),
        severity=severity,
        technique=technique,
        timestamp=datetime.utcnow().isoformat(),
        origin_label=origin_label,
        latitude=str(lat),
        longitude=str(lon),
        country_code=country,
        shockwave=shockwave_flag
    )

    db.add(alert)
    db.commit()
    db.close()


    payload = {
        "severity": severity,
        "technique": technique,
        "origin_label": origin_label,
        "latitude": lat,
        "longitude": lon,
        "country_code": country,
        "shockwave": shockwave_flag == "true"
    }

    await broadcast(payload)

    return {"risk_score": risk, "severity": severity}

@app.get("/alerts")
def alerts():
    db = SessionLocal()
    data = db.query(Alert).order_by(Alert.timestamp.desc()).all()
    db.close()
    return data

@app.get("/attack-paths")
def attack_paths():
    return []

# =========================================================
# DASHBOARD ROUTE
# =========================================================

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
<!DOCTYPE html>
<html>
<head>
<title>LayerSeven SOC Command Center</title>
<script src="https://unpkg.com/globe.gl"></script>

<style>
body { margin:0; background:black; overflow:hidden; color:#00ffff; font-family:monospace;}
#globeViz { width:100vw; height:100vh; }

.panel {
 position:absolute;
 background:rgba(0,10,25,.85);
 padding:8px;
 border:1px solid #00ffff55;
 border-radius:6px;
 font-size:12px;
}

#legend { left:10px; top:10px; width:180px; }
#intel { right:10px; top:10px; width:230px; }
#controls { left:10px; bottom:10px; }
#ticker { bottom:0; width:100%; text-align:center; }

#banner {
 position:absolute;
 top:40%;
 width:100%;
 text-align:center;
 font-size:48px;
 color:#ff0033;
 display:none;
 text-shadow:0 0 25px #ff0033;
}
</style>
</head>
<body>

<div id="globeViz"></div>
<div id="banner">CRITICAL THREAT</div>

<div id="legend" class="panel">
<b>Threat Levels</b><br>
LOW: <span id="lowCount">0</span><br>
MEDIUM: <span id="medCount">0</span><br>
HIGH: <span id="highCount">0</span><br>
CRITICAL: <span id="critCount">0</span>
</div>

<div id="intel" class="panel">
<b>Live Alerts</b>
<div id="intelFeed">Waiting for threats...</div>
</div>

<div id="controls" class="panel">
<button onclick="toggleTraining()">Training Mode</button>
<button onclick="simulateBattle()">Red vs Blue</button>
</div>

<div id="ticker" class="panel"></div>

<script>

const globe = Globe()(document.getElementById('globeViz'))
.globeImageUrl('//unpkg.com/three-globe/example/img/earth-dark.jpg')
.arcAltitudeAutoScale(0.35)
.arcsTransitionDuration(600);

globe.controls().autoRotate = true;

const banner=document.getElementById("banner");
const ticker=document.getElementById("ticker");
const intelFeed=document.getElementById("intelFeed");

const colors={
 LOW:"#00ffff",
 MEDIUM:"#ffaa00",
 HIGH:"#ff5500",
 CRITICAL:"#ff0033"
};

let arcs=[];
let points=[];
let counts={LOW:0, MEDIUM:0, HIGH:0, CRITICAL:0};

function updateLegend(){
 document.getElementById("lowCount").innerText = counts.LOW;
 document.getElementById("medCount").innerText = counts.MEDIUM;
 document.getElementById("highCount").innerText = counts.HIGH;
 document.getElementById("critCount").innerText = counts.CRITICAL;
}

function render(){
 globe.arcsData(arcs);
 globe.pointsData(points)
      .pointAltitude(0.01)
      .pointRadius('size')
      .pointColor('color');
}

/* TRAINING MODE */
let training=false;
function toggleTraining(){
 training=!training;
 ticker.innerHTML = training
   ? "🎯 TRAINING MODE ACTIVE"
   : "LIVE OPERATIONS MODE";
 document.body.style.background = training ? "#001a22" : "black";
}

/* RED VS BLUE */
function simulateBattle(){
 ticker.innerHTML="⚔ RED vs BLUE ENGAGEMENT";
 document.body.style.background="#220000";
 setTimeout(()=>document.body.style.background="black",800);
}

/* add alert visuals */
function addAlert(alert){

 const severity = alert.severity;
 const color = colors[severity] || "#ffffff";

 counts[severity]++;

 const lat = parseFloat(alert.latitude);
 const lng = parseFloat(alert.longitude);

 if(isNaN(lat) || isNaN(lng)) return;

 points.push({ lat: lat, lng: lng, size: 0.45, color: color });

 arcs.push({
   startLat: lat,
   startLng: lng,
   endLat: 41.59,
   endLng: -93.62,
   color: color,
   stroke: severity==="CRITICAL" ? 2.6 : 1.2
 });

 if(severity === "CRITICAL"){
   banner.style.display="block";
   setTimeout(()=>banner.style.display="none",1400);
   globe.pointOfView({lat:lat,lng:lng,altitude:1.3},1600);
 }

 ticker.innerHTML = `⚠ ${severity} • ${alert.technique}`;
 intelFeed.innerHTML = `${alert.origin_label} — ${alert.technique}`;
}

/* load existing alerts */
async function loadExisting(){
 const alerts=await fetch('/alerts').then(r=>r.json());
 alerts.forEach(addAlert);
 render();
 updateLegend();
}

/* live websocket alerts */
const ws = new WebSocket(`wss://${location.host}/ws`);

ws.onmessage = (event) => {
 const alert = JSON.parse(event.data);
 addAlert(alert);
 render();
 updateLegend();
};

loadExisting();

</script>

</body>
</html>
"""

# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
def health():
    return {"status": "ok"}
















