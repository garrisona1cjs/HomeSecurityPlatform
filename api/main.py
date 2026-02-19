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
<title>LayerSeven SOC War Room</title>
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

#queue { right:10px; top:10px; width:240px; max-height:300px; overflow:auto;}
#matrix { left:10px; bottom:10px; }
#ticker { bottom:0; width:100%; text-align:center; }

.matrix-cell {
 width:20px; height:20px; display:inline-block; margin:1px;
 background:#001a22;
}

.heat { background:#ff0033; }

</style>
</head>
<body>

<div id="globeViz"></div>

<div id="queue" class="panel"><b>Alert Queue</b><div id="alerts"></div></div>
<div id="matrix" class="panel"><b>MITRE Matrix</b><br><div id="mitre"></div></div>
<div id="ticker" class="panel"></div>



<script>
const globe = Globe()(document.getElementById('globeViz'))
.globeImageUrl('//unpkg.com/three-globe/example/img/earth-dark.jpg');

globe.controls().autoRotate = true;



const ticker=document.getElementById("ticker");
const queue=document.getElementById("alerts");
const matrix=document.getElementById("mitre");

let heat={};
let cameraIndex=0;

// cinematic camera rotation
const cameraViews=[
 {lat:20,lng:-40,altitude:2},
 {lat:35,lng:100,altitude:2},
 {lat:-20,lng:-60,altitude:2}
];

setInterval(()=>{
 cameraIndex=(cameraIndex+1)%cameraViews.length;
 globe.pointOfView(cameraViews[cameraIndex],2000);
},8000);

// build MITRE matrix
for(let i=0;i<40;i++){
 const cell=document.createElement("div");
 cell.className="matrix-cell";
 matrix.appendChild(cell);
}

function updateMatrix(){
 const cells=document.querySelectorAll(".matrix-cell");
 const idx=Math.floor(Math.random()*cells.length);
 cells[idx].classList.add("heat");
}

// ransomware simulation
function ransomwareEvent(){
 ticker.innerHTML="🚨 RANSOMWARE DEPLOYMENT DETECTED";
 document.body.style.background="#220000";
 setTimeout(()=>document.body.style.background="black",2000);
}

async function load(){
 const paths=await fetch('/attack-paths').then(r=>r.json());
 const alerts=await fetch('/alerts').then(r=>r.json());
 const arcs=[];

 queue.innerHTML="";
 alerts.slice(0,6).forEach(a=>{
   queue.innerHTML += `<div>${a.severity} • ${a.technique}</div>`;
 });

 if(Math.random()<0.08) ransomwareEvent();

 paths.forEach(p=>{
   const levels=["LOW","MEDIUM","HIGH","CRITICAL"];
   const sev=levels[Math.floor(Math.random()*4)];

   const key=p.from.toString();
   heat[key]=(heat[key]||0)+1;

   arcs.push({
     startLat:p.from[0],
     startLng:p.from[1],
     endLat:p.to[0],
     endLng:p.to[1],
     color:"#ff0033",
     stroke:1.2 + heat[key]*0.2
   });

   updateMatrix();
 });

 globe.arcsData(arcs);
}

load();
setInterval(load,3500);
</script>
</body>
</html>
"""






