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

# OPTIONAL GEOIP (SAFE LOAD)
geo_reader = None
if os.path.exists("GeoLite2-City.mmdb"):
    try:
        import geoip2.database
        geo_reader = geoip2.database.Reader("GeoLite2-City.mmdb")
        print("✅ GeoIP database loaded")
    except Exception as e:
        print("GeoIP load failed:", e)
else:
    print("GeoLite2 database not found — map will use demo data")

# -----------------------------
# Database
# -----------------------------

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

app = FastAPI(title="LayerSeven Security Platform", version="10.0")

# serve logo/static files
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
# Register Agent
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
# Report Devices
# -----------------------------

@app.post("/report")
def report_devices(report: DeviceReport, x_api_key: str = Header(None)):
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

    new_devices, missing_devices = [], []
    mac_changes, vendor_changes = [], []

    for ip, dev in current.items():
        if ip not in prev:
            new_devices.append(dev)
        else:
            if prev[ip]["mac"] != dev["mac"]:
                mac_changes.append(ip)
            if prev[ip]["vendor"] != dev["vendor"]:
                vendor_changes.append(ip)

    for ip in prev:
        if ip not in current:
            missing_devices.append(ip)

    SAFE = ["Apple","Samsung","Intel","Dell","HP","Cisco","Microsoft","Google","Amazon"]

    rogue_devices = []
    for d in new_devices:
        if d["vendor"] == "Unknown":
            rogue_devices.append({"ip": d["ip"], "reason":"Unknown vendor"})
        elif not any(v.lower() in d["vendor"].lower() for v in SAFE):
            rogue_devices.append({"ip": d["ip"], "vendor": d["vendor"]})

    # Risk Score
    risk = 40*len(new_devices) + 15*len(missing_devices)
    if mac_changes: risk += 100
    if vendor_changes: risk += 60
    if rogue_devices: risk += 120

    if risk == 0: severity="INFO"
    elif risk < 40: severity="LOW"
    elif risk < 80: severity="MEDIUM"
    elif risk < 120: severity="HIGH"
    else: severity="CRITICAL"

    summary = {
        "risk_score": risk,
        "severity": severity,
        "new_devices": new_devices,
        "missing_devices": missing_devices,
        "rogue_devices": rogue_devices
    }

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

    return {"changes": summary}

# -----------------------------
# Alerts API
# -----------------------------

@app.get("/alerts")
def alerts():
    db = SessionLocal()
    a = db.query(Alert).order_by(Alert.timestamp.desc()).all()
    db.close()
    return a

# -----------------------------
# Geo endpoint
# -----------------------------

@app.get("/threat-feed")
def threat_feed():
    data=[]
    db = SessionLocal()
    alerts=db.query(Alert).all()
    db.close()
    


    for a in alerts:
        if geo_reader:
            try:
                r=geo_reader.city("8.8.8.8")
                data.append({"lat":r.location.latitude,"lon":r.location.longitude})
            except:
                pass
        else:
            data.append({"lat":37.77,"lon":-122.41})  # demo

    return data

# -----------------------------
# Dashboard
# -----------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
<html>
<head>
<title>LayerSeven SOC</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

</head>
<body style="background:#0f172a;color:white;font-family:Arial">

<h1>LayerSeven Security Operations Center</h1>

<div id="ticker" style="background:#020617;padding:10px"></div>

<h2>Recent Alerts</h2>
<div id="alerts"></div>

<h2>Threat Map</h2>
<div id="map" style="height:300px;background:#020617"></div>

<script>
async function load(){
 const alerts=await fetch('/alerts').then(r=>r.json());
 const feed=await fetch('/threat-feed').then(r=>r.json());

 document.getElementById('ticker').innerHTML =
   alerts.slice(0,5).map(a=>a.severity+" threat detected").join(" | ");

 document.getElementById('alerts').innerHTML =
   alerts.slice(0,5).map(a=>{
     let c={"LOW":"yellow","MEDIUM":"orange","HIGH":"red","CRITICAL":"magenta"}[a.severity];
     return `<div style="color:${c}">${a.severity} — ${a.risk_score}</div>`
   }).join("");

 document.getElementById('map').innerHTML =
   feed.map(f=>`🌎 ${f.lat}, ${f.lon}`).join("<br>");
}

load();
setInterval(load,5000);
</script>

</body>
</html>
"""






