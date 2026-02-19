from fastapi import FastAPI, Header, WebSocket, WebSocketDisconnect
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
# Auto Schema Fix
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
<title>LayerSeven SOC Command Center</title>
<script src="https://unpkg.com/globe.gl"></script>

<style>
body { margin:0; background:black; overflow:hidden; color:#00ffff; font-family:monospace;}
#globeViz { width:100vw; height:100vh; }

/* HUD panels */
.panel {
 position:absolute;
 background:rgba(0,10,25,.85);
 padding:10px;
 border:1px solid #00ffff55;
 border-radius:6px;
 font-size:12px;
}

#legend { left:10px; top:10px; }
#stats { right:10px; top:10px; }
#ticker { bottom:0; width:100%; text-align:center; }
#executive { left:10px; bottom:10px; }

.hud-line {
 position:absolute;
 border-top:1px solid #00ffff22;
 width:100%;
 top:50%;
}
</style>
</head>
<body>

<div id="globeViz"></div>
<div class="hud-line"></div>

<div id="legend" class="panel">
<b>Threat Legend</b><br>
<span style="color:#00ffff">LOW</span><br>
<span style="color:#ffaa00">MEDIUM</span><br>
<span style="color:#ff5500">HIGH</span><br>
<span style="color:#ff0033">CRITICAL</span>
</div>

<div id="stats" class="panel">
<b>Attack Counters</b><br>
Total: <span id="total">0</span><br>
Critical: <span id="critical">0</span>
</div>

<div id="executive" class="panel">
<b>Wallboard Mode</b><br>
<button onclick="toggleWall()">Toggle Executive Mode</button>
</div>

<div id="ticker" class="panel"></div>

<audio id="criticalSound" src="https://assets.mixkit.co/active_storage/sfx/2869/2869-preview.mp3"></audio>
<audio id="highSound" src="https://assets.mixkit.co/active_storage/sfx/2571/2571-preview.mp3"></audio>

<script>
const globe = Globe()(document.getElementById('globeViz'))
.globeImageUrl('//unpkg.com/three-globe/example/img/earth-dark.jpg');

globe.controls().autoRotate = true;

const severityColors={
 LOW:"#00ffff",
 MEDIUM:"#ffaa00",
 HIGH:"#ff5500",
 CRITICAL:"#ff0033"
};

let total=0;
let criticalCount=0;
let wallMode=false;

const ticker=document.getElementById("ticker");
const critSound=document.getElementById("criticalSound");
const highSound=document.getElementById("highSound");

function toggleWall(){
 wallMode=!wallMode;
 document.getElementById("legend").style.display=wallMode?"none":"block";
}

function playSound(sev){
 if(sev==="CRITICAL"){ critSound.currentTime=0; critSound.play().catch(()=>{}); }
 else if(sev==="HIGH"){ highSound.currentTime=0; highSound.play().catch(()=>{}); }
}

async function load(){
 const paths=await fetch('/attack-paths').then(r=>r.json());
 const alerts=await fetch('/alerts').then(r=>r.json());
 const arcs=[];

 alerts.forEach(a=>{
   ticker.innerHTML=`⚠ ${a.severity} • ${a.technique}`;
 });

 paths.forEach(p=>{
   const levels=["LOW","MEDIUM","HIGH","CRITICAL"];
   const sev=levels[Math.floor(Math.random()*4)];
   const color=severityColors[sev];

   total++;
   if(sev==="CRITICAL") criticalCount++;

   document.getElementById("total").innerText=total;
   document.getElementById("critical").innerText=criticalCount;

   playSound(sev);

   arcs.push({
     startLat:p.from[0],
     startLng:p.from[1],
     endLat:p.to[0],
     endLng:p.to[1],
     color:color,
     stroke: sev==="CRITICAL"?2.5:1.2
   });

   if(sev==="CRITICAL"){
     globe.pointsData([...globe.pointsData(),{lat:p.to[0],lng:p.to[1],size:2}])
       .pointColor(()=>"#ff0033");
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






