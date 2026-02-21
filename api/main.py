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
# TRAINING MODE + RED vs BLUE STATE
# =========================================================

training_mode = False
red_count = 0
blue_blocks = 0

# =========================================================
# SURGE DETECTION (for grid overlay)
# =========================================================

recent_alerts = []
SURGE_WINDOW = 10   # seconds
SURGE_THRESHOLD = 20  # alerts in window

from datetime import timedelta

def detect_surge():
    now = datetime.utcnow()

    while recent_alerts and now - recent_alerts[0] > timedelta(seconds=SURGE_WINDOW):
        recent_alerts.pop(0)

    return len(recent_alerts) >= SURGE_THRESHOLD

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


       # track surge activity
    recent_alerts.append(datetime.utcnow())
    surge = detect_surge()

    payload = {
        "severity": severity,
        "technique": technique,
        "origin_label": origin_label,
        "latitude": lat,
        "longitude": lon,
        "country_code": country,
        "shockwave": shockwave_flag == "true",

        # SAFE ADDITIONS (do not break dashboard)
        "training": training_mode,
        "team": "red",
        "surge": surge
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
# TRAINING MODE CONTROL
# =========================================================

@app.post("/training/on")
def training_on():
    global training_mode
    training_mode = True
    return {"training": True}

@app.post("/training/off")
def training_off():
    global training_mode
    training_mode = False
    return {"training": False}

# =========================================================
# RED vs BLUE SIMULATION
# =========================================================

@app.post("/simulate")
async def simulate(source_ip: str, team: str = "red"):

    global red_count, blue_blocks

    origin_label, lat, lon, country = geo_lookup_ip(source_ip)

    if team == "red":
        red_count += 1
    else:
        blue_blocks += 1

    payload = {
        "severity": "HIGH",
        "technique": "Simulation",
        "origin_label": origin_label,
        "latitude": lat,
        "longitude": lon,
        "country_code": country,
        "shockwave": False,
        "training": True,
        "team": team
    }

    await broadcast(payload)
    return {"simulated": True}

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
body { margin:0; background:black; overflow:hidden; font-family:monospace;}
#globeViz { width:100vw; height:100vh; }

.panel {
 position:absolute;
 background:rgba(0,10,25,.85);
 padding:8px;
 border:1px solid #00ffff55;
 border-radius:6px;
 font-size:12px;
 color:#00ffff;
}

#legend { left:10px; top:10px; }
#intel { right:10px; top:10px; width:230px; }

#ticker { bottom:0; width:100%; text-align:center; }

#banner {
 position:absolute;
 top:40%;
 width:100%;
 text-align:center;
 font-size:48px;
 color:#ff0033;
 display:none;
 text-shadow:0 0 30px #ff0033;
}
</style>
</head>
<body>

<div id="globeViz"></div>
<div id="banner">CRITICAL THREAT</div>

<div id="legend" class="panel">
LOW <span id="low">0</span><br>
MED <span id="med">0</span><br>
HIGH <span id="high">0</span><br>
CRIT <span id="crit">0</span>
</div>

<div id="intel" class="panel">
<b>Live Intel</b>
<div id="feed">Monitoring…</div>
</div>

<div id="ticker" class="panel"></div>

<script>

const globe = Globe()(document.getElementById('globeViz'))
.globeImageUrl('//unpkg.com/three-globe/example/img/earth-dark.jpg')
.arcAltitudeAutoScale(0.45)
.arcsTransitionDuration(0);

globe.controls().autoRotate = true;
globe.controls().autoRotateSpeed = 0.35;

const banner = document.getElementById("banner");
const feed = document.getElementById("feed");
const ticker = document.getElementById("ticker");

let arcs=[], points=[], rings=[], labels=[], packets=[], heat=[];
let counts={LOW:0,MEDIUM:0,HIGH:0,CRITICAL:0};

const colors={
 LOW:"#00ffff",
 MEDIUM:"#ffaa00",
 HIGH:"#ff5500",
 CRITICAL:"#ff0033"
};

/* ---------- RENDER ---------- */

function render(){
 globe.arcsData(arcs)
   .arcStroke('stroke')
   .arcColor('color')
   .arcDashLength(0.3)
   .arcDashGap(0.08)
   .arcDashAnimateTime(900);

 globe.pointsData(points)
   .pointRadius('size')
   .pointColor('color')
   .pointAltitude(0.02);

 globe.ringsData(rings)
   .ringMaxRadius('maxR')
   .ringPropagationSpeed(3)
   .ringRepeatPeriod(900);

 globe.labelsData(labels)
   .labelText('text')
   .labelColor(()=>"#ffffff")
   .labelDotRadius(0.3);

 globe.pathsData(packets)
   .pathPoints('points')
   .pathColor(()=>"#00ffff")
   .pathDashLength(0.4)
   .pathDashAnimateTime(600);

 globe.hexPolygonsData(heat)
   .hexPolygonColor(d=>d.color)
   .hexPolygonAltitude(d=>d.alt);
}

/* ---------- ADD ALERT ---------- */

function addAlert(alert){

 const lat=parseFloat(alert.latitude);
 const lng=parseFloat(alert.longitude);
 if(isNaN(lat)||isNaN(lng)) return;

 const sev=alert.severity;
 const color=colors[sev];

 counts[sev]++;

document.getElementById("low").textContent = counts.LOW;
document.getElementById("med").textContent = counts.MEDIUM;
document.getElementById("high").textContent = counts.HIGH;
document.getElementById("crit").textContent = counts.CRITICAL;

 // glowing origin
 points.push({lat,lng,size:0.5,color});

 // neon beam trail
 arcs.push({
   startLat:lat,startLng:lng,
   endLat:41.59,endLng:-93.62,
   color:[color,color],
   stroke: sev==="CRITICAL"?3:1.5
 });

 // impact flash at SOC
 rings.push({lat:41.59,lng:-93.62,maxR:5});

 // packet tracer animation
 packets.push({
   points:[
     [lat,lng],
     [41.59,-93.62]
   ]
 });

 // heatmap intensity
heat.push({
  type: "Polygon",
  coordinates: [[
    [lng, lat],
    [lng + 0.4, lat],
    [lng + 0.4, lat + 0.4],
    [lng, lat + 0.4],
    [lng, lat]
  ]],
  color: color,
  alt: 0.03
});

 // country flag
 if(alert.country_code){
   labels.push({
     lat,lng,
     text:String.fromCodePoint(...[...alert.country_code]
       .map(c=>127397+c.charCodeAt()))
   });
 }

 // CRITICAL shockwave & zoom
 if(sev==="CRITICAL"){
   banner.style.display="block";
   setTimeout(()=>banner.style.display="none",1500);

   rings.push({lat,lng,maxR:8});

   globe.controls().autoRotate=false;
   globe.pointOfView({lat,lng,altitude:0.6},1800);

   setTimeout(()=>{
     globe.pointOfView({altitude:2.3},2500);
     globe.controls().autoRotate=true;
   },3500);
 }

 feed.innerHTML = alert.origin_label;
 ticker.innerHTML = sev + " • " + alert.technique;

 render();
}

/* ---------- RADAR SWEEP ---------- */

let sweepAngle=0;
setInterval(()=>{
 sweepAngle+=0.05;
 globe.pointOfView({
   lat: Math.sin(sweepAngle)*30,
   lng: sweepAngle*40,
   altitude:2.3
 }, 4000);
},9000);

/* ---------- LOAD & LIVE ---------- */

async function load(){
 const data=await fetch('/alerts').then(r=>r.json());
 data.forEach(addAlert);
}

const ws=new WebSocket(`wss://${location.host}/ws`);
ws.onmessage=e=>addAlert(JSON.parse(e.data));

load();
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
















