# TEST Change
from fastapi import FastAPI, Header, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from datetime import datetime, timedelta
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

<div id="surgeMeter" class="panel" style="left:10px; top:120px; width:140px;">
<b>Threat Surge</b>
<div id="surgeBar" style="
height:10px;
background:#00ffff;
margin-top:6px;
width:0%;
transition:width .4s ease;
"></div>
</div>

<div id="countryPanel" class="panel" style="left:10px; top:250px; width:170px;">
<b>Top Origins</b>
<div id="countries"></div>
</div>

<div id="velocityPanel" class="panel" style="left:10px; top:340px; width:170px;">
<b>Threat Velocity</b>
<div id="velocity">0 / min</div>
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
.arcsTransitionDuration(0)

/* 🔥 Neon Beam Enhancement */
.arcDashLength(0.35)
.arcDashGap(0.06)
.arcDashInitialGap(() => Math.random())
.arcDashAnimateTime(900)
.arcAltitude(0.18)
.arcStroke(() => 1.5);

globe.controls().autoRotate = true;
globe.controls().autoRotateSpeed = 0.65;
globe.controls().enableDamping = true;
globe.controls().dampingFactor = 0.05;

// 🌍 animated atmospheric glow
const atmosphere = document.createElement('div');
atmosphere.style.position="absolute";
atmosphere.style.top=0;
atmosphere.style.left=0;
atmosphere.style.right=0;
atmosphere.style.bottom=0;
atmosphere.style.pointerEvents="none";
atmosphere.style.boxShadow="inset 0 0 120px rgba(0,150,255,0.08)";
document.body.appendChild(atmosphere);

// subtle breathing motion
setInterval(()=>{
  atmosphere.style.boxShadow =
    "inset 0 0 " +
    (100 + Math.sin(Date.now()*0.002)*40) +
    "px rgba(0,150,255,0.08)";
}, 60);

// 🚨 surge grid overlay
const surgeOverlay = document.createElement("div");
surgeOverlay.style.position="absolute";
surgeOverlay.style.top=0;
surgeOverlay.style.left=0;
surgeOverlay.style.right=0;
surgeOverlay.style.bottom=0;
surgeOverlay.style.pointerEvents="none";
surgeOverlay.style.opacity="0";
surgeOverlay.style.background =
"linear-gradient(rgba(255,0,50,0.08) 1px, transparent 1px)," +
"linear-gradient(90deg, rgba(255,0,50,0.08) 1px, transparent 1px)";
surgeOverlay.style.backgroundSize="60px 60px";
document.body.appendChild(surgeOverlay);

// 📡 radar sweep cone (soft radar beam)
const sweepCone = document.createElement("div");
sweepCone.style.position = "absolute";
sweepCone.style.width = "0";
sweepCone.style.height = "0";

/* cone shape */
sweepCone.style.borderLeft = "180px solid transparent";
sweepCone.style.borderRight = "180px solid transparent";
sweepCone.style.borderTop = "340px solid rgba(0,255,255,0.035)";

/* soften & blend */
sweepCone.style.filter = "blur(12px)";
sweepCone.style.mixBlendMode = "screen";

/* center on globe */
sweepCone.style.left = "50%";
sweepCone.style.top = "50%";
sweepCone.style.transform = "translate(-50%, -50%)";
sweepCone.style.transformOrigin = "top center";

sweepCone.style.pointerEvents = "none";

document.body.appendChild(sweepCone);

// 🌌 PARALLAX STARFIELD BACKGROUND
const starCanvas = document.createElement("canvas");
starCanvas.style.position = "absolute";
starCanvas.style.top = 0;
starCanvas.style.left = 0;
starCanvas.style.pointerEvents = "none";
starCanvas.style.zIndex = "-1";
document.body.appendChild(starCanvas);

const starCtx = starCanvas.getContext("2d");

function resizeStars(){
  starCanvas.width = window.innerWidth;
  starCanvas.height = window.innerHeight;
}
resizeStars();
window.addEventListener("resize", resizeStars);

const stars = [];
const STAR_COUNT = 260;

for(let i=0;i<STAR_COUNT;i++){
  stars.push({
    x: Math.random()*window.innerWidth,
    y: Math.random()*window.innerHeight,
    size: Math.random()*1.6,
    depth: Math.random()*0.8 + 0.2,
    twinkle: Math.random()*Math.PI
  });
}

function animateStars(){
  starCtx.clearRect(0,0,starCanvas.width,starCanvas.height);

  const drift = Date.now() * 0.00002;

  stars.forEach(s => {

    // parallax drift
    s.x -= drift * s.depth;

    if(s.x < 0) s.x = starCanvas.width;

    // twinkle brightness
    const brightness = 0.6 + Math.sin(Date.now()*0.002 + s.twinkle)*0.4;

    starCtx.beginPath();
    starCtx.arc(s.x, s.y, s.size, 0, Math.PI*2);
    starCtx.fillStyle = `rgba(180,220,255,${brightness})`;
    starCtx.fill();
  });

  requestAnimationFrame(animateStars);
}

animateStars();

const banner = document.getElementById("banner");
const feed = document.getElementById("feed");
const ticker = document.getElementById("ticker");

let arcs=[], points=[], rings=[], labels=[], packets=[], heat=[], pulses=[], territories=[], satellites=[];
let counts={LOW:0,MEDIUM:0,HIGH:0,CRITICAL:0};
let surgeLevel = 0;

// intelligence & analytics
let clusters = [];
let countryCounts = {};
let alertTimes = [];
let lastVelocity = 0;
let cameraBusy = false;
let recoveringCamera = false;  

// ===== Dynamic Rotation System =====
let baseRotateSpeed = 0.65;
let targetRotateSpeed = 0.65;
let currentRotateSpeed = 0.65;

// Smooth rotation controller
setInterval(()=>{

  if(cameraBusy || recoveringCamera) return;

  // ease toward target speed
  currentRotateSpeed += (targetRotateSpeed - currentRotateSpeed) * 0.08;

  // subtle starfield parallax shift
  stars.forEach(s => {
  s.x -= currentRotateSpeed * 0.05 * s.depth;
});

  globe.controls().autoRotateSpeed = currentRotateSpeed;

}, 40);

function clusterAttack(lat, lng, severity){
  const radius = 3;
  let found = false;

  clusters.forEach(c => {
    const d = Math.hypot(c.lat - lat, c.lng - lng);

    if(d < radius){
      c.count++;
      found = true;

      points.push({
        lat: c.lat,
        lng: c.lng,
        size: 0.6 + c.count * 0.15,
        color:
          c.count > 5 ? "#ff0033" :
          c.count > 3 ? "#ff5500" :
          "#ffaa00"
      });
    }
  });

  if(!found){
    clusters.push({ lat, lng, count: 1 });
  }
}

// 🌍 Threat Pulse Wave Generator
function createPulse(lat, lng, severity){

  const strength =
    severity === "CRITICAL" ? 18 :
    severity === "HIGH" ? 14 :
    severity === "MEDIUM" ? 10 :
    6;

  pulses.push({ lat, lng, maxR: strength });


  setTimeout(()=>{
    pulses.splice(0,1);
  }, 2200);

}

  // 🌍 Threat Territory Zone Builder
function updateTerritory(lat, lng, severity){

  const radius = 5; // zone size
  let found = false;

  territories.forEach(zone => {

    const d = Math.hypot(zone.lat - lat, zone.lng - lng);

    if(d < radius){
      zone.intensity +=
        severity === "CRITICAL" ? 3 :
        severity === "HIGH" ? 2 :
        severity === "MEDIUM" ? 1 :
        0.5;

      found = true;
    }
  });

  if(!found){
    territories.push({
      lat,
      lng,
      intensity: 1
    });
  }

  // decay over time
  setTimeout(()=>{
    territories.forEach(z => z.intensity *= 0.85);
  }, 3000);
}

// 🛰 orbital satellite network
function initSatellites(){

  const ORBIT_COUNT = 6;

  for(let i=0;i<ORBIT_COUNT;i++){
    satellites.push({
      angle: Math.random() * Math.PI * 2,
      altitude: 1.35 + Math.random()*0.25,
      speed: 0.002 + Math.random()*0.002,
      latOffset: Math.random()*40 - 20
    });
  }
}

initSatellites();




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
   .arcDashAnimateTime(900)
   .arcDashInitialGap(() => Math.random())
   .arcDashGap(0.06)
   .arcDashLength(0.35)
   .arcColor(d => d.color)
   .arcAltitude(d => 0.18);

// 🌍 territory danger zones
const zonePoints = territories.map(z => ({
  lat: z.lat,
  lng: z.lng,
  size: Math.min(2.5, z.intensity * 0.4),
  color:
    z.intensity > 6 ? "#ff0033" :
    z.intensity > 3 ? "#ff5500" :
    "#ffaa00"
}));


// 🛰 update satellite positions
const satellitePoints = satellites.map(s => {

  s.angle += s.speed;

  return {
    lat: Math.sin(s.angle) * 50 + s.latOffset,
    lng: s.angle * 57.3,
    size: 0.35,
    color: "#00ffff"
  };
});

// combine all points
globe.pointsData(points.concat(zonePoints, satellitePoints))
  .pointRadius('size')
  .pointColor('color')
  .pointAltitude(0.02);

 globe.ringsData(rings.concat(pulses))
   .ringMaxRadius('maxR')
   .ringPropagationSpeed(3)
   .ringRepeatPeriod(900);

 globe.labelsData(labels)
   .labelText('text')
   .labelColor(()=>"#ffffff")
   .labelDotRadius(0.3);

// fade old packet trails
packets = packets.filter(p => Date.now() - p.created < 8000);

globe.pathsData(packets)
  .pathPoints('points')
  .pathColor(()=>"#00ffff")
  .pathDashLength(0.4)
  .pathDashAnimateTime(600);

globe.hexPolygonsData(heat)
   .hexPolygonGeoJsonGeometry(d => d)
   .hexPolygonColor(d => d.color)
   .hexPolygonAltitude(d => d.alt);
}

/* ---------- ADD ALERT ---------- */

function addAlert(alert){

 const lat=parseFloat(alert.latitude);
 const lng=parseFloat(alert.longitude);
 if(isNaN(lat)||isNaN(lng)) return;

 const sev=alert.severity;
 const color=colors[sev];

 // 🛰 satellites react to threats
satellites.forEach(s => {
  s.speed += sev === "CRITICAL" ? 0.004 :
             sev === "HIGH" ? 0.002 : 0;

  setTimeout(()=> s.speed *= 0.98, 2000);
});

 // adjust rotation intensity by severity
if(sev === "LOW") targetRotateSpeed = baseRotateSpeed;
if(sev === "MEDIUM") targetRotateSpeed = baseRotateSpeed + 0.05;
if(sev === "HIGH") targetRotateSpeed = baseRotateSpeed + 0.12;
if(sev === "CRITICAL") targetRotateSpeed = baseRotateSpeed + 0.22;

 counts[sev]++;

 document.getElementById("low").textContent = counts.LOW;
 document.getElementById("med").textContent = counts.MEDIUM;
 document.getElementById("high").textContent = counts.HIGH;
 document.getElementById("crit").textContent = counts.CRITICAL;

// glowing origin
points.push({
  lat,
  lng,
  size: 0.8,
  color
});

// swarm clustering
clusterAttack(lat, lng, sev);
updateTerritory(lat, lng, sev);

// pulse wave expansion
createPulse(lat, lng, sev);

// neon beam trail
arcs.push({
  startLat: lat,
  startLng: lng,
  endLat: 41.59,
  endLng: -93.62,
  color: [color, color]
});

 // impact flash at SOC
rings.push({
  lat:41.59,
  lng:-93.62,
  maxR:
    sev==="CRITICAL" ? 12 :
    sev==="HIGH" ? 9 :
    sev==="MEDIUM" ? 6 :
    4
});

 // packet tracer animation
packets.push({
  points:[
    [lat,lng],
    [41.59,-93.62]
  ],
  created: Date.now()
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

 
// CRITICAL shockwave & cinematic zoom
if(sev === "CRITICAL" && !cameraBusy){

  cameraBusy = true;
  recoveringCamera = true;

  banner.style.display = "block";
  setTimeout(()=> banner.style.display="none",1500);

  // impact shockwaves
  rings.push({lat,lng,maxR:8});
  rings.push({lat,lng,maxR:11});
  rings.push({lat,lng,maxR:14});

  // satellite pulse response
satellites.forEach(s => {
  rings.push({
    lat: Math.sin(s.angle)*50 + s.latOffset,
    lng: s.angle * 57.3,
    maxR: 5
  });
});

  // stop rotation
  globe.controls().autoRotate = false;

  // cinematic zoom to origin
  globe.pointOfView({lat, lng, altitude:0.6}, 1800);

  setTimeout(()=>{

    // restore neutral orientation
    globe.pointOfView({
      lat: 20,
      lng: 0,
      altitude: 2.3
    }, 2200);

  }, 3500);

  // restart rotation AFTER camera settles
  setTimeout(()=>{

    globe.controls().autoRotate = true;
    targetRotateSpeed = baseRotateSpeed;

    globe.controls().autoRotateSpeed = 0.2;

    if(window.rotationRamp) clearInterval(window.rotationRamp);

    window.rotationRamp = setInterval(()=>{
      globe.controls().autoRotateSpeed += 0.05;
      if(globe.controls().autoRotateSpeed >= 0.65){
        globe.controls().autoRotateSpeed = 0.65;
        clearInterval(window.rotationRamp);
      }
    }, 60);

    recoveringCamera = false;
    cameraBusy = false;

  }, 6000);
}

feed.innerHTML = alert.origin_label;
ticker.innerHTML = sev + " • " + alert.technique;

// 🌎 track top attacking countries
if(alert.country_code){
  countryCounts[alert.country_code] =
    (countryCounts[alert.country_code] || 0) + 1;

  const sorted = Object.entries(countryCounts)
    .sort((a,b)=>b[1]-a[1])
    .slice(0,5);

  document.getElementById("countries").innerHTML =
    sorted.map(c => `${c[0]} : ${c[1]}`).join("<br>");
}

// ⚡ threat velocity tracking
const now = Date.now();
alertTimes.push(now);

// keep last 60 seconds
alertTimes = alertTimes.filter(t => now - t < 60000);

const velocityDiv = document.getElementById("velocity");
if(velocityDiv){
  velocityDiv.textContent = alertTimes.length + " / min";
}

// 🚨 anomaly spike detection
const currentVelocity = alertTimes.length;

if(currentVelocity > lastVelocity + 6){
  banner.innerHTML = "ANOMALOUS TRAFFIC";
  banner.style.display="block";
  setTimeout(()=>banner.style.display="none",1200);
}

lastVelocity = currentVelocity;

 // ===== SURGE METER =====
if(alert.surge){
    surgeLevel = Math.min(100, surgeLevel + 20);
} else {
    surgeLevel = Math.max(0, surgeLevel - 2);
}

if(alert.surge){
  targetRotateSpeed = baseRotateSpeed + 0.35;
}

const bar = document.getElementById("surgeBar");
bar.style.width = surgeLevel + "%";

// 🚨 toggle surge grid
surgeOverlay.style.opacity = surgeLevel > 60 ? 1 : 0;

// 🚨 surge alert flash
if(surgeLevel > 80){
  banner.innerHTML = "SURGE EVENT";
  banner.style.display="block";
  setTimeout(()=>banner.style.display="none",1000);
}

// 🔥 pulse grid during surge
if(surgeLevel > 60){
  surgeOverlay.style.backgroundSize =
    (60 + Math.sin(Date.now()*0.01)*8) + "px " +
    (60 + Math.sin(Date.now()*0.01)*8) + "px";
}

if(surgeLevel > 70){
    bar.style.background = "#ff0033";
}
else if(surgeLevel > 40){
    bar.style.background = "#ffaa00";
}
else{
    bar.style.background = "#00ffff";
}

// gradually return to base speed after activity
setTimeout(()=>{
  targetRotateSpeed = baseRotateSpeed;
}, 4000);

 render();
}

/* ---------- RADAR SWEEP ---------- */

let sweepAngle = 0;

setInterval(()=>{

  // prevent conflict during zoom or recovery
  if(cameraBusy || recoveringCamera) return;

  // ONLY sweep when autoRotate is OFF
  if(!globe.controls().autoRotate){

    sweepAngle += 0.05;

    globe.pointOfView({
      lat: Math.sin(sweepAngle) * 30,
      lng: sweepAngle * 40,
      altitude: 2.3
    }, 4000);
  }

}, 9000);

// animate radar sweep cone
setInterval(()=>{
sweepCone.style.transform =
  "translate(-50%, -50%) rotate(" +
  (Date.now()*0.02 % 360) +
  "deg)";
}, 60);

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
















