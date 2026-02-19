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
# Database Model
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
#intel { right:10px; top:10px; width:240px; }
#controls { left:10px; bottom:10px; }
#ticker { bottom:0; width:100%; text-align:center; }
#counter { right:10px; bottom:10px; }

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
<span style="color:#00ffff">LOW</span>: <span id="lowCount">0</span><br>
<span style="color:#ffaa00">MEDIUM</span>: <span id="medCount">0</span><br>
<span style="color:#ff5500">HIGH</span>: <span id="highCount">0</span><br>
<span style="color:#ff0033">CRITICAL</span>: <span id="critCount">0</span>
</div>

<div id="intel" class="panel"><b>Threat Intel</b><div id="feed"></div></div>

<div id="controls" class="panel">
<button onclick="toggleTraining()">Training Mode</button>
<button onclick="simulateBattle()">Red vs Blue</button>
</div>

<div id="counter" class="panel">
<b>Active Attacks:</b> <span id="attackCount">0</span>
</div>

<div id="ticker" class="panel"></div>



<script>


const globe = Globe()(document.getElementById('globeViz'))
.globeImageUrl('//unpkg.com/three-globe/example/img/earth-dark.jpg');

globe.controls().autoRotate = true;

/* cinematic camera */
const views=[
 {lat:25,lng:-40,altitude:2},
 {lat:40,lng:110,altitude:2},
 {lat:-15,lng:-60,altitude:2}
];
let camIndex=0;
setInterval(()=>{
 camIndex=(camIndex+1)%views.length;
 globe.pointOfView(views[camIndex],2500);
},9000);

/* intel feed */
const feed=document.getElementById("feed");
const intel=[
 "CISA exploitation warning",
 "Botnet C2 surge detected",
 "AbuseIPDB malicious spike",
 "Spamhaus threat escalation",
 "TOR exit node traffic rise"
];
setInterval(()=>{ feed.innerHTML=intel[Math.floor(Math.random()*intel.length)]; },4000);

/* training mode */
let training=false;
const ticker=document.getElementById("ticker");

function toggleTraining(){
 training=!training;
 ticker.innerHTML=training?"🎯 TRAINING MODE ACTIVE":"LIVE OPERATIONS MODE";
 document.body.style.background=training?"#001a22":"black";
}

/* red vs blue simulation */
function simulateBattle(){
 ticker.innerHTML="⚔ RED vs BLUE ENGAGEMENT";
 document.body.style.background="#220000";
 setTimeout(()=>document.body.style.background="black",800);
}



const colors={
 LOW:"#00ffff",
 MEDIUM:"#ffaa00",
 HIGH:"#ff5500",
 CRITICAL:"#ff0033"
};

let heatMap={};



async function load(){
 const paths=await fetch('/attack-paths').then(r=>r.json());
 const alerts=await fetch('/alerts').then(r=>r.json());

 let counts={LOW:0,MEDIUM:0,HIGH:0,CRITICAL:0};
 let arcs=[];
 document.getElementById("attackCount").innerText=paths.length;

 alerts.forEach(a=>{
   ticker.innerHTML=`⚠ ${a.severity} • ${a.technique}`;
 });

 paths.forEach(p=>{
   const levels=["LOW","MEDIUM","HIGH","CRITICAL"];
   const sev=levels[Math.floor(Math.random()*4)];
   counts[sev]++;

   if(sev==="CRITICAL"){
      document.getElementById("banner").style.display="block";
      setTimeout(()=>document.getElementById("banner").style.display="none",1200);
      globe.pointOfView({lat:p.to[0],lng:p.to[1],altitude:1.2},1500);
   }

   const key=p.from.toString();
   heatMap[key]=(heatMap[key]||0)+1;

   globe.pointsData([
    ...globe.pointsData(),
    {lat:p.from[0],lng:p.from[1],size:0.35*heatMap[key]}
   ]).pointColor(()=>"#ff0033");
   



   globe.pointsData([
    ...globe.pointsData(),
    {lat:p.to[0],lng:p.to[1],size:1.6}
   ]).pointColor(()=>"#ff0033");


   arcs.push({
     startLat:p.from[0],
     startLng:p.from[1],
     endLat:p.to[0],
     endLng:p.to[1],
     color:colors[sev],
     stroke: sev==="CRITICAL"?2.6:1.2
   });
 });

 globe.arcsData(arcs);

 document.getElementById("lowCount").innerText=counts.LOW;
 document.getElementById("medCount").innerText=counts.MEDIUM;
 document.getElementById("highCount").innerText=counts.HIGH;
 document.getElementById("critCount").innerText=counts.CRITICAL;
}

load();
setInterval(load,3500);
</script>
</body>
</html>
"""






