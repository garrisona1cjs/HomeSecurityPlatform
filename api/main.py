from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse

from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import List
import uuid
import secrets
import os
import json

from sqlalchemy import create_engine, Column, String, Text
from sqlalchemy.orm import declarative_base, sessionmaker

from mac_vendor_lookup import MacLookup
import geoip2.database

# =============================
# DATABASE
# =============================

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

app = FastAPI(title="LayerSeven SOC API", version="10.0")

# =============================
# VENDOR LOOKUP
# =============================

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

# =============================
# GEO LOCATION
# =============================

geo_reader = None
if os.path.exists("GeoLite2-City.mmdb"):
    geo_reader = geoip2.database.Reader("GeoLite2-City.mmdb")

def get_location(ip):
    if not geo_reader:
        return None
    try:
        r = geo_reader.city(ip)
        return {
            "lat": r.location.latitude,
            "lon": r.location.longitude,
            "city": r.city.name,
            "country": r.country.name
        }
    except:
        return None

# =============================
# MODELS
# =============================

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

# =============================
# SCHEMAS
# =============================

class AgentRegistration(BaseModel):
    hostname: str
    ip_address: str

class DeviceReport(BaseModel):
    agent_id: str
    devices: List[dict]

# =============================
# AUTH
# =============================

def verify_agent(db, agent_id, api_key):
    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent or agent.api_key != api_key:
        raise HTTPException(status_code=401, detail="Invalid agent")

# =============================
# REGISTER
# =============================

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

# =============================
# REPORT
# =============================

@app.post("/report")
def report(report: DeviceReport, x_api_key: str = Header(None)):
    db = SessionLocal()
    verify_agent(db, report.agent_id, x_api_key)

    last = db.query(Report).filter(
        Report.agent_id == report.agent_id
    ).order_by(Report.timestamp.desc()).first()

    prev = {}
    if last:
        for d in json.loads(last.data):
            prev[d["ip"]] = d

    current = {}
    for d in report.devices:
        current[d["ip"]] = {
            "ip": d["ip"],
            "mac": d["mac"],
            "vendor": get_vendor(d["mac"])
        }

    new_devices = []
    missing = []
    mac_changes = []


    for ip, data in current.items():
        if ip not in prev:
            new_devices.append(data)
        elif prev[ip]["mac"] != data["mac"]:
            mac_changes.append(ip)

    for ip in prev:
        if ip not in current:
            missing.append(ip)

    SAFE = ["Apple","Samsung","Intel","Dell","HP","Cisco","Microsoft","Google","Amazon","Raspberry"]

    rogue = []
    for d in new_devices:
        v = d["vendor"]
        if v == "Unknown":
            rogue.append({"ip": d["ip"], "reason": "Unknown vendor"})
        elif not any(s.lower() in v.lower() for s in SAFE):
            rogue.append({"ip": d["ip"], "vendor": v})

    risk = 40*len(new_devices) + 15*len(missing)
    if mac_changes: risk += 100
    if rogue: risk += 120

    if risk == 0: severity="INFO"
    elif risk < 40: severity="LOW"
    elif risk < 80: severity="MEDIUM"
    elif risk < 120: severity="HIGH"
    else: severity="CRITICAL"

    db.add(Report(
        id=str(uuid.uuid4()),
        agent_id=report.agent_id,
        data=json.dumps(list(current.values())),
        timestamp=datetime.utcnow().isoformat()
    ))

    if risk>0:
        db.add(Alert(
            id=str(uuid.uuid4()),
            agent_id=report.agent_id,
            risk_score=str(risk),
            severity=severity,
            timestamp=datetime.utcnow().isoformat()
        ))

    db.commit()
    db.close()

    return {"risk": risk, "severity": severity, "rogue_devices": rogue}

# =============================
# ALERTS
# =============================

@app.get("/alerts")
def alerts():
    db = SessionLocal()
    data = db.query(Alert).order_by(Alert.timestamp.desc()).all()
    db.close()
    return data

@app.get("/alerts/map")
def alert_map():
    db = SessionLocal()
    alerts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(20).all()
    db.close()

    results = []

    for a in alerts:
        loc = get_location("8.8.8.8")
        if loc:
            results.append({
                "lat": loc["lat"],
                "lon": loc["lon"],
                "severity": a.severity,
                "risk": a.risk_score,
                "city": loc["city"],
                "country": loc["country"]
            })
    return results

# =============================
# DASHBOARD
# =============================

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
<html>
<head>
<title>LayerSeven SOC</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
</head>
<body style="background:#0f172a;color:white;font-family:Arial;padding:20px;">

<h1>🛡 LayerSeven SOC Dashboard</h1>

<h2>🌍 Live Threat Map</h2>
<div id="map" style="height:400px;margin-bottom:30px;"></div>

<h2>Recent Alerts</h2>
<div id="alerts"></div>



<script>
let map = L.map('map').setView([20,0],2);

L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);

let markers=[];

async function loadMap(){
 const data=await fetch('/alerts/map').then(r=>r.json());
 markers.forEach(m=>map.removeLayer(m));
 markers=[];
 data.forEach(a=>{
  const color=
   a.severity==="CRITICAL"?"red":
   a.severity==="HIGH"?"orange":
   a.severity==="MEDIUM"?"yellow":
   a.severity==="LOW"?"cyan":"white";

  const m=L.circleMarker([a.lat,a.lon],{radius:12,color:color}).addTo(map);
  m.bindPopup(a.city+", "+a.country+"<br>"+a.severity+" risk:"+a.risk);

  let size=12;
  setInterval(()=>{size=size==12?18:12;m.setRadius(size)},700);
  markers.push(m);
 });
}

async function loadAlerts(){
 const alerts=await fetch('/alerts').then(r=>r.json());
 document.getElementById("alerts").innerHTML=
  alerts.slice(0,5).map(a=>a.severity+" risk:"+a.risk_score).join("<br>");
}

function refresh(){
 loadMap();
 loadAlerts();
}

refresh();
setInterval(refresh,10000);
</script
>
</body>
</html>
"""






