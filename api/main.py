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
# Optional GeoIP Support
# -----------------------------
geo_reader = None
if os.path.exists("GeoLite2-City.mmdb"):
    try:
        import geoip2.database
        geo_reader = geoip2.database.Reader("GeoLite2-City.mmdb")
        print("✅ GeoIP loaded")
    except:
        print("GeoIP failed to load")

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

class Report(Base):
    __tablename__ = "reports"
    id = Column(String, primary_key=True)
    agent_id = Column(String)
    data = Column(Text)
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
# Report
# -----------------------------

@app.post("/report")
def report_devices(report: DeviceReport, x_api_key: str = Header(None)):
    db = SessionLocal()
    verify_agent(db, report.agent_id, x_api_key)

    new_devices = []
    for d in report.devices:
        vendor = get_vendor(d["mac"])
        new_devices.append({
            "ip": d["ip"],
            "mac": d["mac"],
            "vendor": vendor
        })

    risk = len(new_devices) * 40
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
# Threat Feed (Map Data)
# -----------------------------

@app.get("/threat-feed")
def threat_feed():

    db = SessionLocal()
    alerts = db.query(Alert).all()
    db.close()

    feed = []

    for alert in alerts:
        # Demo attack source locations (worldwide)
        feed.append({
            "lat": 37.77,
            "lon": -122.41
        })
        feed.append({
            "lat": 51.50,
            "lon": -0.12
        })
        feed.append({
            "lat": 35.68,
            "lon": 139.69
        })
        feed.append({
            "lat": 55.75,
            "lon": 37.61
        })

    return feed

# -----------------------------
# Dashboard with Animated Map
# -----------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
<!DOCTYPE html>
<html>
<head>
<title>LayerSeven SOC</title>

<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>

<style>
body { margin:0; background:#0f172a; color:white; font-family:Arial;}
#map { height:500px; }
.ticker {
  background:#020617;
  padding:10px;
  font-weight:bold;
}
.pulse {
  background:red;
  border-radius:50%;
  width:12px;
  height:12px;
  position:absolute;
  animation:pulse 1.5s infinite;
}
@keyframes pulse {
  0% {transform:scale(.5); opacity:1;}
  100% {transform:scale(3); opacity:0;}
}
</style>
</head>
<body>

<h1 style="padding:10px">🌐 LayerSeven Threat Map</h1>
<div class="ticker" id="ticker">Loading alerts...</div>
<div id="map"></div>

<script>
const map = L.map('map').setView([20,0],2);

L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution:'© OpenStreetMap'
}).addTo(map);

let markers = [];

async function loadFeed(){
    const alerts = await fetch('/alerts').then(r=>r.json());
    const feed = await fetch('/threat-feed').then(r=>r.json());

    document.getElementById("ticker").innerHTML =
        alerts.slice(0,5).map(a => a.severity + " threat detected").join(" | ");

    markers.forEach(m=>map.removeLayer(m));
    markers = [];

    feed.forEach(p=>{
        const marker = L.circleMarker([p.lat, p.lon], {
            radius:8,
            color:"red",
            fillOpacity:0.7
        }).addTo(map);

        markers.push(marker);
    });
}

loadFeed();
setInterval(loadFeed, 5000);
</script>

</body>
</html>
"""






