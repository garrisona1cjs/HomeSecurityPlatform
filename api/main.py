# =========================================================
# IMPORTS
# =========================================================

from fastapi import FastAPI, Header, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import List
import uuid, secrets, os, random, asyncio
import geoip2.database

from sqlalchemy import create_engine, Column, String, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

from ipwhois import IPWhois


# =========================================================
# GEOIP CONFIG
# =========================================================

GEOIP_DB = os.getenv("GEOIP_DB", "geoip/GeoLite2-City.mmdb")

reader = None
if os.path.exists(GEOIP_DB):
    reader = geoip2.database.Reader(GEOIP_DB)



def geo_lookup_ip(ip):

    try:
        if reader:
          geo = reader.city(ip)
        else:
         raise Exception()

        city = geo.city.name or "Unknown"
        country = geo.country.iso_code or "??"
        lat = geo.location.latitude or 0
        lon = geo.location.longitude or 0

        origin_label = f"{city}, {country}"

    except:
        origin_label, lat, lon, country = "Unknown", 0, 0, "??"

    # ASN + ISP lookup
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1)

        asn = res.get("asn", "N/A")
        isp = res.get("network", {}).get("name", "Unknown")

    except:
        asn = "N/A"
        isp = "Unknown"

    return origin_label, lat, lon, country, isp, asn


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
# AGENT MODEL (AUTHENTICATION)
# =========================================================

class Agent(Base):

    __tablename__ = "agents"

    agent_id = Column(String, primary_key=True)
    hostname = Column(String)
    ip_address = Column(String)
    api_key = Column(String)
    created_at = Column(String) 


# =========================================================
# INCIDENT MODEL
# =========================================================

class Incident(Base):
    
    __tablename__ = "incidents"

    id = Column(String, primary_key=True)
    source_ip = Column(String)
    asn = Column(String)
    country_code = Column(String)

    severity = Column(String)

    alert_count = Column(String)

    status = Column(String)

    first_seen = Column(String)
    last_seen = Column(String)


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
# INCIDENT CORRELATION ENGINE
# =========================================================

CORRELATION_WINDOW = 120  # seconds


def correlate_incident(db, source_ip, asn, country_code, severity):

    now = datetime.utcnow()
    window_start = now - timedelta(seconds=CORRELATION_WINDOW)

    incident = db.query(Incident).filter(
        Incident.source_ip == source_ip,
        Incident.asn == asn
    ).first()

    if incident:
        
        incident.alert_count = str(int(incident.alert_count) + 1)
        incident.last_seen = now.isoformat()

        db.commit()
        return incident

    incident = Incident(
        id=str(uuid.uuid4()),
        source_ip=source_ip,
        asn=asn,
        country_code=country_code,
        severity=severity,
        alert_count="1",
        status="NEW",
        first_seen=now.isoformat(),
        last_seen=now.isoformat()
    )

    db.add(incident)
    db.commit()

    return incident

# =========================================================
# TRAINING + SURGE DETECTION
# =========================================================

# =========================================================
# THREAT CAMPAIGN DETECTION ENGINE
# =========================================================

# =========================================================
# ASN THREAT INTELLIGENCE ENGINE
# =========================================================

asn_threat_tracker = {}

ASN_WINDOW = 300  # seconds
ASN_ESCALATION_THRESHOLD = 8


def track_asn_threat(asn):

    now = datetime.utcnow().timestamp()

    if asn not in asn_threat_tracker:
        asn_threat_tracker[asn] = []

    asn_threat_tracker[asn].append(now)

    # remove expired activity
    asn_threat_tracker[asn] = [
        t for t in asn_threat_tracker[asn]
        if now - t < ASN_WINDOW
    ]

    attack_count = len(asn_threat_tracker[asn])

    if attack_count >= ASN_ESCALATION_THRESHOLD:
        return "HOSTILE_NETWORK", attack_count

    return None, attack_count

# =========================================================
# BOTNET DETECTION ENGINE
# =========================================================

botnet_tracker = {}

BOTNET_WINDOW = 120
BOTNET_IP_THRESHOLD = 10
BOTNET_COUNTRY_THRESHOLD = 4


def detect_botnet(source_ip, asn, country):

    now = datetime.utcnow().timestamp()

    if asn not in botnet_tracker:
        botnet_tracker[asn] = {
            "ips": set(),
            "countries": set(),
            "timestamps": []
        }

    tracker = botnet_tracker[asn]

    tracker["ips"].add(source_ip)
    tracker["countries"].add(country)
    tracker["timestamps"].append(now)

    # cleanup old timestamps
    tracker["timestamps"] = [
        t for t in tracker["timestamps"]
        if now - t < BOTNET_WINDOW
    ]

    ip_count = len(tracker["ips"])
    country_count = len(tracker["countries"])


    if ip_count >= BOTNET_IP_THRESHOLD and country_count >= BOTNET_COUNTRY_THRESHOLD:
        return "BOTNET_CLUSTER", ip_count, country_count

    return None, ip_count, country_count

# =========================================================
# AUTOMATED DEFENSE ENGINE
# =========================================================

blocked_ips = set()
defense_log = []

AUTO_BLOCK_THRESHOLD = 3


def evaluate_defense(source_ip, severity, botnet_flag, asn_flag):

    block_reason = None

    # block immediately if botnet cluster
    if botnet_flag == "BOTNET_CLUSTER":
        block_reason = "BOTNET_ACTIVITY"

    # block hostile ASN infrastructure
    elif asn_flag == "HOSTILE_NETWORK" and severity in ["HIGH", "CRITICAL"]:
        block_reason = "HOSTILE_ASN"

    # block repeated critical attacks
    elif severity == "CRITICAL":
        block_reason = "CRITICAL_ATTACK"

    if block_reason:

        if source_ip not in blocked_ips:

            blocked_ips.add(source_ip)

            defense_log.append({
                "ip": source_ip,
                "reason": block_reason,
                "timestamp": datetime.utcnow().isoformat()
            })

            return True, block_reason

    return False, None

   

campaign_tracker = {
    "asn_activity": {},
    "country_activity": {},
    "ip_activity": {},
}

CAMPAIGN_WINDOW = 60  # seconds
BOTNET_THRESHOLD = 6
ASN_ATTACK_THRESHOLD = 4
COUNTRY_CAMPAIGN_THRESHOLD = 5


def detect_campaign(source_ip, asn, country):

    now = datetime.utcnow().timestamp()

    # track activity
    campaign_tracker["ip_activity"].setdefault(source_ip, []).append(now)
    campaign_tracker["asn_activity"].setdefault(asn, []).append(now)
    campaign_tracker["country_activity"].setdefault(country, []).append(now)

    # cleanup old entries
    for category in campaign_tracker.values():
        
        for key in list(category.keys()):
            
            category[key] = [t for t in category[key] if now - t < CAMPAIGN_WINDOW]

            if not category[key]:
                del category[key]

    # detection logic
    if source_ip in campaign_tracker["ip_activity"] and len(campaign_tracker["ip_activity"][source_ip]) >= BOTNET_THRESHOLD:
        return "BOTNET_RECON_WAVE"

    if asn in campaign_tracker["asn_activity"] and len(campaign_tracker["asn_activity"][asn]) >= ASN_ATTACK_THRESHOLD:
        return "ASN_COORDINATED_ATTACK"

    if country in campaign_tracker["country_activity"] and len(campaign_tracker["country_activity"][country]) >= COUNTRY_CAMPAIGN_THRESHOLD:
        return "MULTI_ORIGIN_CAMPAIGN"

    return None

training_mode = False




recent_alerts = []

SURGE_WINDOW = 10
SURGE_THRESHOLD = 20


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
# AGENT AUTHENTICATION
# =========================================================

def authenticate_agent(db, agent_id, api_key, request_ip):

    agent = db.query(Agent).filter(
        Agent.agent_id == agent_id
    ).first()

    if not agent:
        return False

    if agent.api_key != api_key:
        return False

    # IP binding validation
    if agent.ip_address != request_ip:
        return False

    return True


# =========================================================
# REGISTER
# =========================================================

@app.post("/register")
def register(agent: AgentRegistration):

    db = SessionLocal()
    


    agent_id = str(uuid.uuid4())
    api_key = secrets.token_hex(32)

    new_agent = Agent(
        agent_id=agent_id,
        hostname=agent.hostname,
        ip_address=agent.ip_address,
        api_key=api_key,
        created_at=datetime.utcnow().isoformat()
    )

    db.add(new_agent)
    db.commit()
    db.close()

    return {
        "agent_id": agent_id,
        "api_key": api_key
    }


# =========================================================
# REPORT DEVICES
# =========================================================

@app.post("/report")
async def report_devices(
    report: DeviceReport,
    request: Request,
    x_api_key: str = Header(None)
):
    

    db = SessionLocal()
    client_ip = request.client.host


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

    origin_label, lat, lon, country, isp_name, asn = geo_lookup_ip(ip_addr)

    campaign = detect_campaign(ip_addr, asn, country)

    # ASN threat intelligence
    asn_flag, asn_attack_count = track_asn_threat(asn)

    # botnet detection
    botnet_flag, botnet_ips, botnet_countries = detect_botnet(
        ip_addr,
        asn,
        country
    )

    # automated defense evaluation
    blocked, block_reason = evaluate_defense(
        ip_addr,
        severity,
        botnet_flag,
        asn_flag
    )

    technique = random.choice([
        "T1110 Brute Force",
        "T1078 Valid Accounts",
        "T1046 Network Scan",
        "T1059 Command Exec",
        "T1566 Phishing"
    ])

    # escalate severity if ASN is hostile
    if asn_flag == "HOSTILE_NETWORK":

        if severity == "LOW":
            severity = "MEDIUM"

        elif severity == "MEDIUM":
            severity = "HIGH"

        elif severity == "HIGH":
            severity = "CRITICAL" 

    # escalate severity if botnet activity detected
    if botnet_flag == "BOTNET_CLUSTER":

        if severity == "LOW":
            severity = "HIGH"

        elif severity == "MEDIUM":
            severity = "CRITICAL"

    shockwave_flag = severity == "CRITICAL"

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
        shockwave=str(shockwave_flag)
    )

    db.add(alert)
    db.commit()
    correlate_incident(
        db,
        ip_addr,
        asn,
        country,
        severity
    )
    
    db.close()

    # surge tracking
    recent_alerts.append(datetime.utcnow())
    surge = detect_surge()

    payload = {

        "severity": severity,
        "technique": technique,
        "origin_label": origin_label,


        "asn_attack_count": asn_attack_count,
        "asn_flag": asn_flag,

        "botnet_flag": botnet_flag,

        "blocked": blocked,
        "block_reason": block_reason,
        "botnet_ips": botnet_ips,
        "botnet_countries": botnet_countries,
        "latitude": lat,
        "longitude": lon,
        "country_code": country,
        "source_ip": ip_addr,
        "isp": isp_name,
        "asn": asn,
        "shockwave": shockwave_flag,
        "training": training_mode,
        "team": "red",
        "surge": surge
    }

    await broadcast(payload)

    return {"risk_score": risk, "severity": severity}



# =========================================================
# SIMULATION
# =========================================================

@app.post("/simulate")
async def simulate(source_ip: str, team: str = "red"):

    origin_label, lat, lon, country, isp_name, asn = geo_lookup_ip(source_ip)

    payload = {
        "severity": "HIGH",
        "technique": "Simulation",
        "origin_label": origin_label,
        "latitude": lat,
        "longitude": lon,
        "country_code": country,
        "source_ip": source_ip,
        "isp": isp_name,
        "asn": asn,
        "shockwave": False,
        "training": True,
        "team": team
    }

    await broadcast(payload)
    return {"simulated": True}

# =========================================================
# ALERT HISTORY
# =========================================================

@app.get("/alerts")
def alerts():
    
    
    db = SessionLocal()

    data = db.query(Alert).order_by(Alert.timestamp.desc()).all()

    db.close()

    return data

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

<div id="geoHUD" class="panel" style="
left:50%;
bottom:50px;
transform:translateX(-50%);
font-size:14px;
padding:6px 14px;
display:none;
text-align:center;">
</div>

<script>

const globe = Globe()(document.getElementById('globeViz'));

globe
  .globeImageUrl('//unpkg.com/three-globe/example/img/earth-dark.jpg')
  .arcAltitudeAutoScale(0.45)
  .arcsTransitionDuration(0)
  .arcDashLength(0.35)
  .arcDashGap(0.06)
  .arcDashInitialGap(() => Math.random())
  .arcDashAnimateTime(1600)
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

// 🛡 magnetic planetary shield layer
const shield = document.createElement("div");
shield.style.position = "absolute";
shield.style.top = 0;
shield.style.left = 0;
shield.style.right = 0;
shield.style.bottom = 0;
shield.style.pointerEvents = "none";
shield.style.opacity = "0.25";
shield.style.mixBlendMode = "screen";
shield.style.background =
  "radial-gradient(circle at center, rgba(0,255,255,0.08), rgba(0,0,0,0) 60%)";
document.body.appendChild(shield);

// subtle breathing motion
setInterval(()=>{
  atmosphere.style.boxShadow =
    "inset 0 0 " +
    (100 + Math.sin(Date.now()*0.002)*40) +
    "px rgba(0,150,255,0.08)";
}, 120);

// subtle magnetic flow shimmer
setInterval(()=>{

  const energy = 0.05 + Math.sin(Date.now()*0.002) * 0.02;

  shield.style.background =
    `radial-gradient(circle at center,
      rgba(0,255,255,${energy}),
      rgba(0,0,0,0) 60%)`;

}, 120);

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
const STAR_COUNT = 120;

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
const geoHUD = document.getElementById("geoHUD");

let arcs=[], points=[], rings=[], labels=[], packets=[], heat=[], pulses=[], territories=[], satellites=[], orbitRings=[];
// GLOBAL THREAT PRESSURE SYSTEM
let pressureZones = [];
const MAX_PRESSURE_ZONES = 120;
// EVENT BUFFER SYSTEM
let alertQueue = [];

let processingQueue = false;

let counts = {LOW:0,MEDIUM:0,HIGH:0,CRITICAL:0};

let surgeLevel = 0;

/* =====================================
   SOC EVENT GOVERNOR
===================================== */

let MAX_QUEUE = 400;
let EVENT_DROP_COUNT = 0;
let dynamicBatchSize = 8;

const MAX_TERRITORIES = 80;
const MAX_CLUSTERS = 60;

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
        size: Math.min(3, 0.6 + c.count * 0.15),
        color:
          c.count > 5 ? "#ff0033" :
          c.count > 3 ? "#ff5500" :
          "#ffaa00"
      });
    }
  });

  if(!found){
    clusters.push({ lat, lng, count: 1 });

    if (clusters.length > MAX_CLUSTERS) clusters.shift();
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

// 🎯 Precision investigation zoom
function investigateLocation(lat, lng, intel){

  if (!intel) return;

  if (!intel.country) {
    intel.country = "";
  }

  if(cameraBusy || recoveringCamera) return;

  cameraBusy = true;


  globe.controls().autoRotate = false;

  const flag = intel.country
    ? String.fromCodePoint(...[...intel.country]
        .map(c => 127397 + c.charCodeAt()))
    : "";

  // build intelligence display
  geoHUD.style.display = "block";
  geoHUD.innerHTML = `
    <div style="font-size:16px; color:#00ffff;">
      📍 ${intel.label || "Unknown Origin"} ${flag}
    </div>

    <div style="margin-top:4px;">
      Lat ${lat.toFixed(2)} | Lng ${lng.toFixed(2)}
    </div>

    ${intel.ip ? `<div>IP: ${intel.ip}</div>` : ""}

    ${intel.isp ? `<div>ISP: ${intel.isp}</div>` : ""}

    ${intel.asn ? `<div>ASN: ${intel.asn}</div>` : ""}

    <div style="color:${intel.color}; font-weight:bold;">
      ${intel.severity} • ${intel.technique}
    </div>

    ${intel.training ? `<div style="color:#ffaa00;">TRAINING EVENT</div>` : ""}
  `;

  // zoom to origin
  globe.pointOfView({ lat, lng, altitude: 0.9 }, 1400);

  // return to neutral
  setTimeout(()=>{

    globe.pointOfView({ lat: 20, lng: 0, altitude: 2.3 }, 1800);

  }, 1800);

  // restore rotation & hide HUD
  setTimeout(()=>{

    geoHUD.style.display = "none";

    globe.controls().autoRotate = true;

    globe.controls().autoRotateSpeed = 0.2;

    if(window.rotationRamp) clearInterval(window.rotationRamp);

    window.rotationRamp = setInterval(()=>{
      globe.controls().autoRotateSpeed += 0.05;
      if(globe.controls().autoRotateSpeed >= baseRotateSpeed){
        globe.controls().autoRotateSpeed = baseRotateSpeed;
        clearInterval(window.rotationRamp);
      }
    }, 60);

    cameraBusy = false;

  }, 3600);
}

  // 🌍 Threat Territory Zone Builder
function updateThreatPressure(lat, lng, severity){

  const radius = 8;
  let found = false;

  pressureZones.forEach(zone => {

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

    pressureZones.push({
      lat: lat,
      lng: lng,
      intensity: 1
    });

    if (pressureZones.length > MAX_PRESSURE_ZONES){
      pressureZones.shift();
    }

  }

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

// 🛰 create orbital defense rings
function initOrbitRings(){

  const ringCount = 3;

  for(let i=0;i<ringCount;i++){
    orbitRings.push({
      angle: Math.random() * Math.PI * 2,
      tilt: Math.random() * 60 - 30,
      altitude: 1.15 + i * 0.1,
      speed: 0.0008 + i * 0.0003
    });
  }
}

initOrbitRings();






const colors={
 LOW:"#00ffff",
 MEDIUM:"#ffaa00",
 HIGH:"#ff5500",
 CRITICAL:"#ff0033"
};








const LIMITS = {
  arcs: 120,
  points: 200,
  rings: 80,
  packets: 120,
  heat: 40,
  labels: 120
};

function clamp(arr, limit){
  if(arr.length > limit){
    arr.splice(0, arr.length - limit);
  }
}

// ======================================
// SOC RENDER LIMIT CONFIG
// ======================================
const RENDER_LIMITS = {
  arcs: 120,
  points: 200,
  rings: 80,
  packets: 120,
  heat: 40,
  labels: 120,
  queue: 150
};

let lastFrame = 0;
let FRAME_LIMIT = 90;

/* adaptive FPS control */

setInterval(()=>{

  if(alertQueue.length > 200){

    FRAME_LIMIT = 140;

  }else if(alertQueue.length > 100){

    FRAME_LIMIT = 110;

  }else{

    FRAME_LIMIT = 90;

  }

},2000);

let renderPending = false;

/* ---------- RENDER ---------- */

function render(){

const now = Date.now();
if(now - lastFrame < FRAME_LIMIT) return;
lastFrame = now;



clamp(arcs, RENDER_LIMITS.arcs);
clamp(points, RENDER_LIMITS.points);
clamp(rings, RENDER_LIMITS.rings);
clamp(packets, RENDER_LIMITS.packets);
clamp(heat, RENDER_LIMITS.heat);
clamp(labels, RENDER_LIMITS.labels);

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



// global threat pressure glow
// 🌍 Global Threat Pressure Field
const pressurePoints = pressureZones.map(z => ({

  lat: z.lat,
  lng: z.lng,

  size: Math.min(6, z.intensity * 0.5),

  color:
    z.intensity > 9 ? "#ff0033" :
    z.intensity > 6 ? "#ff5500" :
    z.intensity > 3 ? "#ffaa00" :
    "#00ffff"

}));

// 🛰 orbital defense rings
const ringPaths = orbitRings.map(r => {

  r.angle += r.speed;

  const pathPoints = [];

  for(let a=0; a<=360; a+=5){
    const rad = (a + r.angle * 57) * Math.PI / 180;

    pathPoints.push([
      Math.sin(rad) * (90 - r.tilt),
      a,
      r.altitude
    ]);
  }

  return {
    points: pathPoints,
    color: "rgba(0,255,255,0.55)"
  };
});


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
globe.pointsData(points.concat(pressurePoints, satellitePoints))
  .pointRadius('size')
  .pointColor('color')
  .pointAltitude(d => Math.min(0.08, d.size * 0.02));

  // pressure pulse expansion
pressureZones.forEach(z => {

  if(z.intensity > 8){

    rings.push({
      lat: z.lat,
      lng: z.lng,
      maxR: 14
    });

  }

});

 globe.ringsData(rings.concat(pulses))
   .ringMaxRadius('maxR')
   .ringPropagationSpeed(3)
   .ringRepeatPeriod(900);

 globe.labelsData(labels)
   .labelText('text')
   .labelColor(()=>"#ffffff")
   .labelDotRadius(0.3);

// fade old packet trails
for (let i = packets.length - 1; i >= 0; i--) {
  if (now - packets[i].created > 8000) {
    packets.splice(i, 1);
  }
}

globe.pathsData([
  ...packets,
  ...ringPaths
])
  .pathPoints('points')
  .pathColor(d => d.color || "#00ffff")
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

const color = colors[sev];


// 🛰 satellites react to threats
satellites.forEach(s => {
  s.speed = Math.min(
  s.speed +
  (sev === "CRITICAL" ? 0.004 :
   sev === "HIGH" ? 0.002 : 0),
  0.01
);

r.speed = Math.min(
    r.speed +
    (sev === "CRITICAL" ? 0.002 :
    sev === "HIGH" ? 0.001 : 0),
    0.01
);

  setTimeout(() => s.speed *= 0.98, 2000);
});

// 🛰 defense rings react to attacks
orbitRings.forEach(r => {
  r.speed = Math.min(
    r.speed +
    (sev === "CRITICAL" ? 0.002 :
    sev === "HIGH" ? 0.001 : 0),
    0.01
  );

  setTimeout(() => r.speed *= 0.9, 2500);
});


// 🎛 rotation intensity + investigation logic
if (sev === "LOW") {
  targetRotateSpeed = baseRotateSpeed;
}

if (sev === "MEDIUM") {
  targetRotateSpeed = baseRotateSpeed + 0.05;

  // occasional investigation zoom
  if (Math.random() < 0.35) {
    investigateLocation(lat, lng, {
      label: alert.origin_label,
      country: alert.country_code,
      ip: alert.source_ip,
      isp: alert.isp,
      asn: alert.asn,
      severity: sev,
      technique: alert.technique,
      training: alert.training,
      color: colors[sev]
    });
  }
}

if (sev === "HIGH") {
  targetRotateSpeed = baseRotateSpeed + 0.12;

  // 🎯 zoom to investigate attack origin
investigateLocation(lat, lng, {
  label: alert.origin_label,
  country: alert.country_code,
  ip: alert.source_ip,
  isp: alert.isp,
  asn: alert.asn,
  severity: sev,
  technique: alert.technique,
  training: alert.training,
  color: colors[sev]
});
}

if (sev === "CRITICAL") {
  targetRotateSpeed = baseRotateSpeed + 0.22;
  // cinematic zoom handled later
}
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

updateThreatPressure(lat, lng, sev);

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

 // planetary shield ripple pulse
rings.push({
  lat: 0,
  lng: 0,
  maxR: 120
}); 

  // satellite pulse response
satellites.forEach(s => {
  rings.push({
    lat: Math.sin(s.angle)*50 + s.latOffset,
    lng: s.angle * 57.3,
    maxR: 5
  });
});

// shield flash effect
orbitRings.forEach(r => {
  r.speed += 0.004;
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

feed.innerHTML =
  alert.origin_label +
  (alert.isp ? "<br>ISP: " + alert.isp : "") +
  (alert.asn ? "<br>ASN: " + alert.asn : "");
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
if (velocityDiv) {
  velocityDiv.textContent = alertTimes.length + " / min";
}

// 🚨 anomaly spike detection
const currentVelocity = alertTimes.length;

if (currentVelocity > lastVelocity + 6) {
  banner.innerHTML = "ANOMALOUS TRAFFIC";
  banner.style.display = "block";
  setTimeout(() => banner.style.display = "none", 1200);
}

lastVelocity = currentVelocity;

// ===== SURGE METER =====
if (alert.surge) {
  surgeLevel = Math.min(100, surgeLevel + 20);
} else {
  surgeLevel = Math.max(0, surgeLevel - 2);
}

if (alert.surge) {
  targetRotateSpeed = baseRotateSpeed + 0.35;
}

const bar = document.getElementById("surgeBar");
bar.style.width = surgeLevel + "%";

// 🛡 shield strengthens with surge
shield.style.opacity = Math.min(0.65, 0.25 + surgeLevel * 0.004);

// 🚨 toggle surge grid
surgeOverlay.style.opacity = surgeLevel > 60 ? 1 : 0;

// 🚨 SURGE ALERT FLASH + SHIELD OVERLOAD
if (surgeLevel > 80) {

  shield.style.background =
    "radial-gradient(circle at center, rgba(255,0,80,0.25), rgba(0,0,0,0) 65%)";

  banner.innerHTML = "SURGE EVENT";
  banner.style.display = "block";

  setTimeout(() => banner.style.display = "none", 1000);

} else {

  shield.style.background =
    "radial-gradient(circle at center, rgba(0,255,255,0.08), rgba(0,0,0,0) 60%)";
}

// 🎚 SURGE BAR COLOR LOGIC
if (surgeLevel > 70) {
  bar.style.background = "#ff0033";
}
else if (surgeLevel > 40) {
  bar.style.background = "#ffaa00";
}
else {
  bar.style.background = "#00ffff";
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


}

/* =====================================
   SOC CONTROLLED RENDER LOOP
===================================== */

function renderLoop(){

  render();

  requestAnimationFrame(renderLoop);

}

renderLoop();

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

// ======================================
// WebGL Memory Guard
// ======================================
function trim(arr, max){
  if(arr.length > max){
    arr.splice(0, arr.length - max);
  }
}

setInterval(()=>{

  trim(arcs,120);
  trim(points,200);
  trim(rings,80);
  trim(packets,120);
  trim(heat,40);
  trim(labels,120);

}, 5000);

// animate radar sweep cone
setInterval(()=>{
sweepCone.style.transform =
  "translate(-50%, -50%) rotate(" +
  (Date.now()*0.02 % 360) +
  "deg)";
}, 120);

// SOC Render Scheduler
setInterval(() => {

  if (processingQueue || renderPending) return;

  processingQueue = true;
  renderPending = true;

  /* adaptive load control */

  if(alertQueue.length > 300){

    dynamicBatchSize = 18;

  } else if(alertQueue.length > 150){

    dynamicBatchSize = 12;

  } else {

    dynamicBatchSize = 8;

  }

  let batchSize = Math.min(dynamicBatchSize, alertQueue.length);

  while (alertQueue.length > 0 && batchSize > 0) {

    const alert = alertQueue.shift();
    addAlert(alert);

    batchSize--;

  }

  processingQueue = false;
  renderPending = false;

}, 100);

// threat pressure decay
setInterval(()=>{

  pressureZones.forEach(z => {
    z.intensity *= 0.92;
  });

  pressureZones = pressureZones
  .filter(z => z.intensity > 0.25)
  .slice(-80);

}, 2000);

// ======================================
// Dashboard Watchdog
// ======================================
setInterval(()=>{

  const mem = performance.memory;

  if(mem && mem.usedJSHeapSize > 350000000){

    console.warn("SOC Dashboard memory reset triggered");

    arcs.length = 0;
    points.length = 0;
    rings.length = 0;
    packets.length = 0;
    heat.length = 0;
    labels.length = 0;
    pressureZones.length = 0;
    clusters.length = 0;

  }

}, 10000);

// ======================================
// Idle Cleanup
// ======================================
setInterval(()=>{

  if(alertQueue.length === 0){

    clamp(arcs,80);
    clamp(points,120);
    clamp(rings,60);
    clamp(packets,60);
    clamp(heat,20);
    clamp(labels,80);

  }

},15000);

/* ---------- LOAD & LIVE ---------- */

async function load(){
 const data=await fetch('/alerts').then(r=>r.json());
 data.forEach(addAlert);
}

const protocol = location.protocol === "https:" ? "wss" : "ws";
const ws = new WebSocket(`${protocol}://${location.host}/ws`);
ws.onmessage = e => {

  const alert = JSON.parse(e.data);



  // backpressure protection
  if(alertQueue.length > MAX_QUEUE){

  EVENT_DROP_COUNT++;

  if(EVENT_DROP_COUNT % 100 === 0){
    console.warn("SOC Governor dropping events:", EVENT_DROP_COUNT);
  }

}else{

  alertQueue.push(alert);

}

};

load();

/* ======================================
   WebGL Context Recovery
====================================== */

window.addEventListener("webglcontextlost", function(e){

  console.warn("WebGL context lost - reloading dashboard");

  e.preventDefault();

  setTimeout(()=>{
    location.reload();
  },2000);

}, false);
</script>

</body>
</html>
"""

# =========================================================
# DEFENSE STATUS
# =========================================================

@app.get("/defense/blocked")
def get_blocked():

    return {
        "blocked_ips": list(blocked_ips),
        "events": defense_log
    }


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
def health():
    return {"status": "ok"}


















