from fastapi import FastAPI, Header, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from datetime import datetime
from typing import List
import uuid, secrets, os, random

from sqlalchemy import create_engine, Column, String, inspect
from sqlalchemy.orm import declarative_base, sessionmaker








DATABASE_URL = os.getenv("DATABASE_URL")



engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


app = FastAPI(title="LayerSeven Security Platform")






app.mount("/static", StaticFiles(directory="static"), name="static")




# -----------------------------
# Model
# -----------------------------



class Alert(Base):
    __tablename__ = "alerts"
    id = Column(String, primary_key=True)
    agent_id = Column(String)
    risk_score = Column(String)
    severity = Column(String)
    technique = Column(String)
    timestamp = Column(String)





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



techniques = [
    "T1110 Brute Force",
    "T1078 Valid Accounts",
    "T1046 Network Scannin",
    "T1059 Command Exec",
    "T1566 Phishing"
]

# -----------------------------
# API ROUTES
# -----------------------------

@app.post("/register")
def register(agent: AgentRegistration):
    return {"agent_id": str(uuid.uuid4()), "api_key": secrets.token_hex(16)}

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



@app.get("/alerts")
def alerts():
    db = SessionLocal()
    data = db.query(Alert).order_by(Alert.timestamp.desc()).all()
    db.close()
    return data

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
# DASHBOARD
# -----------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
<!DOCTYPE html>
<html>
<head>
<title>LayerSeven Cyber Range</title>
<script src="https://unpkg.com/globe.gl"></script>

<style>
body { margin:0; background:black; overflow:hidden; color:#00ffff; font-family:monospace;}
#globeViz { width:100vw; height:100vh; }


.panel {
 position:absolute;
 background:rgba(0,10,25,.85);
 padding:10px;
 border:1px solid #00ffff55;
 border-radius:6px;
 font-size:12px;
}

#intel { right:10px; top:10px; width:260px; }
#training { left:10px; bottom:10px; }
#ticker { bottom:0; width:100%; text-align:center; }






</style>
</head>
<body>

<div id="globeViz"></div>

<div id="intel" class="panel"><b>Threat Intel Feed</b><div id="feed"></div></div>
<div id="training" class="panel">
<button onclick="toggleTraining()">Training Mode</button>
<button onclick="simulateBattle()">Red vs Blue</button>
</div>
<div id="ticker" class="panel"></div>



<script>
const globe = Globe()(document.getElementById('globeViz'))
.globeImageUrl('//unpkg.com/three-globe/example/img/earth-dark.jpg');

globe.controls().autoRotate = true;



const ticker=document.getElementById("ticker");
const feed=document.getElementById("feed");

let training=false;
let threatScore=0;

// real-world intel simulation
const intelSources=[
 "CISA: Active exploitation detected",
 "AbuseIPDB: malicious IP surge",
 "Emerging Threats: botnet C2 activity",
 "TOR exit nodes spike observed",
 "Spamhaus: new malware distribution wave"
];

function intelFeed(){
 if(Math.random()<0.5){
   feed.innerHTML=intelSources[Math.floor(Math.random()*intelSources.length)];
 }
}
setInterval(intelFeed,4000);

// AI prediction paths
function predictPath(origin){
 return {
   startLat:origin[0],
   startLng:origin[1],
   endLat:origin[0]+(Math.random()*30-15),
   endLng:origin[1]+(Math.random()*30-15),
   color:"#ff00ff",
   stroke:0.8
 };
}

// playbook automation
function autoRespond(){
 if(threatScore>20){
   ticker.innerHTML="🛡 Automated containment executed";
   threatScore-=5;
 }
}

// red vs blue simulation
function simulateBattle(){
 ticker.innerHTML="⚔ Red vs Blue engagement started";
}

// training mode
function toggleTraining(){
 training=!training;
 ticker.innerHTML=training ? "🎯 Training Mode Enabled" : "Training Mode Disabled";
}

// cyber range attack loader
async function load(){
 const paths=await fetch('/attack-paths').then(r=>r.json());

 const arcs=[];
 

 paths.forEach(p=>{
   threatScore+= training ? 1 : 2;

   arcs.push({
     startLat:p.from[0],
     startLng:p.from[1],
     endLat:p.to[0],
     endLng:p.to[1],
     color:"#ff0033",
     stroke:1.2
   });

   // AI prediction
   arcs.push(predictPath(p.from));
 });

 globe.arcsData(arcs);
 autoRespond();
}

load();
setInterval(load,3500);
</script>
</body>
</html>
"""






