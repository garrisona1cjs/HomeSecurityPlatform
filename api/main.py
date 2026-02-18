from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from datetime import datetime
from typing import List
import uuid, secrets, os, random

from sqlalchemy import create_engine, Column, String
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
    timestamp = Column(String)
    technique = Column(String)

from sqlalchemy import inspect

# ensure alerts table schema is correct
inspector = inspect(engine)

if "alerts" in inspector.get_table_names():
    columns = [col["name"] for col in inspector.get_columns("alerts")]

    # if schema is outdated, recreate table
    if "technique" not in columns:
        Alert.__table__.drop(engine)

Base.metadata.create_all(bind=engine)

# -----------------------------
# MITRE Technique Map
# -----------------------------

techniques = [
    ("T1110", "Brute Force"),
    ("T1078", "Valid Accounts"),
    ("T1046", "Network Scanning"),
    ("T1059", "Command Execution"),
    ("T1566", "Phishing"),
]

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
# 🌐 WebSocket Hub
# -----------------------------

connections = set()

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    connections.add(ws)



    for c in connections:
        await c.send_text("JOIN")

    try:
        while True:
            msg = await ws.receive_text()
            for c in connections:
                await c.send_text(msg)
    except WebSocketDisconnect:
        connections.remove(ws)
        for c in connections:
            await c.send_text("LEAVE")

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
body { margin:0; background:black; color:#00ffff; font-family:monospace; overflow:hidden;}

#globeViz { width:100vw; height:100vh; }


.panel {
 position:absolute;
 background:rgba(0,10,25,0.85);
 padding:10px;
 border-radius:6px;
 font-size:12px;
}
#status { left:10px; top:40px; }
#intel { right:10px; top:40px; width:220px; }
</style>
</head>
<body>

<div id="globeViz"></div>

<div id="status" class="panel">
Threat Level: <span id="level">LOW</span><br>
Analysts: <span id="users">0</span>
</div>

<div id="intel" class="panel">
<b>Threat Intel</b>
<div id="feed"></div>
</div>

<script>
const globe = Globe()(document.getElementById('globeViz'))
.globeImageUrl('//unpkg.com/three-globe/example/img/earth-dark.jpg')
.backgroundImageUrl('//unpkg.com/three-globe/example/img/night-sky.png');

globe.controls().autoRotate = true;


const wsProtocol = location.protocol === "https:" ? "wss" : "ws";
const ws = new WebSocket(`${wsProtocol}://${location.host}/ws`);

let users=0;
let threatScore=0;
let anomalyMap={};

// analyst sync
ws.onmessage = e => {
    if(e.data==="JOIN") users++;
    else if(e.data==="LEAVE") users--;
    users=Math.max(0,users);
    document.getElementById("users").innerHTML=users;
};

// anomaly detection
function detectAnomaly(lat,lng){
    const key=lat.toFixed(0)+lng.toFixed(0);
    anomalyMap[key]=(anomalyMap[key]||0)+1;
    if(anomalyMap[key]>3){
        globe.pointsData([...globe.pointsData(),{lat:lat,lng:lng,size:2}])
             .pointColor(()=>"#ff0033");
    }
}

// MITRE mapping
const mitre = [
 "T1110 Brute Force",
 "T1078 Valid Accounts",
 "T1046 Network Scannin",
 "T1059 Command Exec",
 "T1566 Phishing"
];

// threat intel feed simulation
function intelFeed(){
    const iocs=[
      "Malicious ASN flagged",
      "Botnet infrastructure detected",
      "Known ransomware node",
      "Credential harvesting domain"
    ];
    if(Math.random()<.4){
      document.getElementById("feed").innerHTML=
        iocs[Math.floor(Math.random()*iocs.length)];
    }
}
setInterval(intelFeed,4000);

// incident response automation
function respond(){
    if(threatScore>20){
        threatScore-=5;
        console.log("Auto mitigation executed");
    }
}

// threat level
function updateThreat(){
    if(threatScore>25) level.innerHTML="CRITICAL";
    else if(threatScore>15) level.innerHTML="HIGH";
    else if(threatScore>8) level.innerHTML="MEDIUM";
}

// load attacks + live alerts
async function load(){
    const paths=await fetch('/attack-paths').then(r=>r.json());
    const arcs=[];
    
    for(const p of paths){

        detectAnomaly(p.from[0],p.from[1]);

        threatScore+=2;

        arcs.push({
            startLat:p.from[0],
            startLng:p.from[1],
            endLat:p.to[0],
            endLng:p.to[1],
            color:"#ff0033",
            stroke:1.2
        });

        // live alert pulse
        globe.pointsData([...globe.pointsData(),
          {lat:p.to[0],lng:p.to[1],size:0.7}])
          .pointColor(()=>"#ffff00");

        console.log("Technique:", mitre[Math.floor(Math.random()*mitre.length)]);
    }

    globe.arcsData(arcs);
    respond();
    updateThreat();
}

load();
setInterval(load,3500);
</script>
</body>
</html>
"""






