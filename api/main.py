from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from datetime import datetime
from typing import List
import uuid, secrets, os, random

from sqlalchemy import create_engine, Column, String, inspect
from sqlalchemy.orm import declarative_base, sessionmaker





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
# Models
# -----------------------------



class Alert(Base):
    __tablename__ = "alerts"
    id = Column(String, primary_key=True)
    agent_id = Column(String)
    risk_score = Column(String)
    severity = Column(String)
    technique = Column(String)
    timestamp = Column(String)

# -----------------------------
# Auto Schema Fix (free-tier safe)
# -----------------------------



inspector = inspect(engine)

if "alerts" in inspector.get_table_names():
    cols = [c["name"] for c in inspector.get_columns("alerts")]
    if "technique" not in cols:
        Alert.__table__.drop(engine)

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
# MITRE Techniques
# -----------------------------

techniques = [
    "T1110 Brute Force",
    "T1078 Valid Accounts",
    "T1046 Network Scannin",
    "T1059 Command Exec",
    "T1566 Phishing"
]

# -----------------------------
# Register Agent
# -----------------------------

@app.post("/register")
def register(agent: AgentRegistration):
    return {
        "agent_id": str(uuid.uuid4()),
        "api_key": secrets.token_hex(16)
    }

# -----------------------------
# Report → Create Alert
# -----------------------------

@app.post("/report")
def report_devices(report: DeviceReport, x_api_key: str = Header(None)):
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

    db.add(Alert(
        id=str(uuid.uuid4()),
        agent_id=report.agent_id,
        risk_score=str(risk),
        severity=severity,
        technique=random.choice(techniques),
        timestamp=datetime.utcnow().isoformat()
    ))

    db.commit()
    db.close()

    return {"risk_score": risk, "severity": severity}

# -----------------------------
# Alerts API
# -----------------------------

@app.get("/alerts")
def get_alerts():
    db = SessionLocal()
    alerts = db.query(Alert).order_by(Alert.timestamp.desc()).all()
    db.close()
    return alerts

# -----------------------------
# Attack Feed
# -----------------------------

@app.get("/attack-paths")
def attack_paths():

    return [
        {"from":[55.75,37.61], "to":[41.59,-93.62]},
        {"from":[35.68,139.69], "to":[41.59,-93.62]},
        {"from":[51.50,-0.12], "to":[41.59,-93.62]},
        {"from":[-23.55,-46.63], "to":[41.59,-93.62]},
        {"from":[37.77,-122.41], "to":[41.59,-93.62]}
    ]

# -----------------------------
# WebSocket Hub
# -----------------------------

connections = set()

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    connections.add(ws)

    



    try:
        while True:
            msg = await ws.receive_text()
            for c in connections:
                await c.send_text(msg)
    except WebSocketDisconnect:
        connections.remove(ws)


# -----------------------------
# SOC Dashboard
# -----------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
<!DOCTYPE html>
<html>
<head>
<title>LayerSeven SOC Intelligence Console</title>
<script src="https://unpkg.com/globe.gl"></script>

<style>
body { margin:0; background:black; overflow:hidden; }
#globeViz { width:100vw; height:100vh; }



</style>
</head>
<body>

<div id="globeViz"></div>






<script>
const globe = Globe()(document.getElementById('globeViz'))
.globeImageUrl('//unpkg.com/three-globe/example/img/earth-dark.jpg')
.backgroundImageUrl('//unpkg.com/three-globe/example/img/night-sky.png');

globe.controls().autoRotate = true;

const severityColors = {
 LOW:"#00ffff",
 MEDIUM:"#ffaa00",
 HIGH:"#ff5500",
 CRITICAL:"#ff0033"
};

let heatMap = {};

const ticker = document.createElement("div");
ticker.style.position="absolute";
ticker.style.bottom="0";
ticker.style.width="100%";
ticker.style.background="rgba(0,0,0,.7)";
ticker.style.color="#00ffff";
ticker.style.textAlign="center";
ticker.style.padding="4px";
document.body.appendChild(ticker);

const popup=document.createElement("div");
popup.style.position="absolute";
popup.style.right="20px";
popup.style.bottom="40px";
popup.style.background="rgba(0,10,25,.9)";
popup.style.padding="10px";
popup.style.display="none";
document.body.appendChild(popup);

function criticalFlash(lat,lng){
 globe.pointsData([...globe.pointsData(),{lat:lat,lng:lng,size:2}])
 .pointColor(()=>"#ff0033");
 document.body.style.background="#220000";
 setTimeout(()=>document.body.style.background="black",150);
}

function showMitre(t){
 popup.innerHTML="<b>MITRE:</b><br>"+t;
 popup.style.display="block";
 setTimeout(()=>popup.style.display="none",2500);
}

function heatGlow(lat,lng){
 const key=lat.toFixed(0)+lng.toFixed(0);
 heatMap[key]=(heatMap[key]||0)+1;
 globe.pointsData([...globe.pointsData(),{
  lat:lat,lng:lng,size:0.5*heatMap[key]
 }]).pointColor(()=>"#ff0033");
}


async function load(){
 const paths=await fetch('/attack-paths').then(r=>r.json());
 const alerts=await fetch('/alerts').then(r=>r.json());
 const arcs=[];

 alerts.forEach(a=>{
  ticker.innerHTML=`⚠ ${a.severity} threat • ${a.technique}`;
 });

 paths.forEach(p=>{
  const severityLevels=["LOW","MEDIUM","HIGH","CRITICAL"];
  const severity=severityLevels[Math.floor(Math.random()*4)];
  const color=severityColors[severity];

  arcs.push({
   startLat:p.from[0],
   startLng:p.from[1],
   endLat:p.to[0],
   endLng:p.to[1],
   color:color,
   stroke: severity==="CRITICAL"?2.5:1.2
  });

  heatGlow(p.from[0],p.from[1]);

  if(severity==="CRITICAL"){
    criticalFlash(p.to[0],p.to[1]);
    showMitre(alerts.length?alerts[0].technique:"T1110");
  }
 });

 globe.arcsData(arcs);
}

load();
setInterval(load,3500);
</script>
</body>
</html>
"""






