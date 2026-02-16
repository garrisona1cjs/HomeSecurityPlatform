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
# Report (generates alerts)
# -----------------------------

@app.post("/report")
def report_devices(report: DeviceReport, x_api_key: str = Header(None)):
    db = SessionLocal()
    verify_agent(db, report.agent_id, x_api_key)

    risk = len(report.devices) * 40
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
# Attack Paths (for map)
# -----------------------------
@app.get("/attack-paths")
def attack_paths():
    # simulated global attack paths → your SOC location
    return [
        {"from":[55.75,37.61], "to":[41.59,-93.62]},  # Moscow → Iowa
        {"from":[35.68,139.69], "to":[41.59,-93.62]}, # Tokyo → Iowa
        {"from":[51.50,-0.12], "to":[41.59,-93.62]},  # London → Iowa
        {"from":[-23.55,-46.63], "to":[41.59,-93.62]},# Brazil → Iowa
        {"from":[37.77,-122.41], "to":[41.59,-93.62]} # SF → Iowa
    ]


# -----------------------------
# LayerSeven Enterprise SOC Console
# -----------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
<!DOCTYPE html>
<html>
<head>
<title>LayerSeven Enterprise SOC Console</title>

<script src="https://unpkg.com/globe.gl"></script>

<style>
body { margin:0; background:black; overflow:hidden; font-family:monospace; color:#00ffff;}

#globeViz { width:100vw; height:100vh; }

.panel {
    position:absolute;
    background:rgba(0,10,25,0.8);
    padding:10px;
    border-radius:6px;

}

#mitre { left:10px; top:40px; width:260px; }
#tickets { right:10px; top:40px; width:260px; }
#collab { right:10px; bottom:10px; width:260px; }
#export { left:10px; bottom:10px; width:260px; }

button, textarea {
    width:100%;
    margin-top:6px;
    background:#001f33;

    border:1px solid #00ffff55;
    color:#00ffff;
    padding:4px;

}
</style>
</head>
<body>

<div id="globeViz"></div>

<div id="mitre" class="panel">
<b>MITRE ATT&CK Heat Matrix</b><br>
<div id="matrix"></div>
</div>

<div id="tickets" class="panel">
<b>Case Tickets</b><br>
<div id="ticketList"></div>
</div>

<div id="collab" class="panel">
<b>Analyst Collaboration</b><br>
<textarea id="notes" rows="4" placeholder="Add investigation notes..."></textarea>
<button onclick="saveNote()">Save Note</button>
<div id="savedNotes"></div>
</div>

<div id="export" class="panel">
<b>Reporting</b><br>
<button onclick="exportTimeline()">Export Campaign Timeline</button>
<button onclick="exportCompliance()">Export Compliance Report</button>
</div>

<script>
const globe = Globe()(document.getElementById('globeViz'))
  .globeImageUrl('//unpkg.com/three-globe/example/img/earth-dark.jpg');

globe.controls().autoRotate = true;

let mitreCounts = {};
let tickets = [];
let timeline = [];

// MITRE techniques
const techniques = [
"T1595 Active Scanning",
"T1110 Brute Force",
"T1046 Network Discovery",
"T1021 Remote Services",
"T1078 Valid Accounts"
];

// update heat matrix
function updateMatrix(tech){
    mitreCounts[tech] = (mitreCounts[tech] || 0) + 1;

    const matrix = document.getElementById("matrix");
    matrix.innerHTML = "";

    Object.keys(mitreCounts).forEach(t=>{
        matrix.innerHTML += t + " [" + mitreCounts[t] + "]<br>";
    });
}

// create SOC ticket
function createTicket(tech){
    const id = "CASE-" + Math.floor(Math.random()*9999);
    tickets.push({id:id, technique:tech});

    const list = document.getElementById("ticketList");
    list.innerHTML += id + " — " + tech + "<br>";
}

// save analyst note
function saveNote(){
    const note = document.getElementById("notes").value;
    if(!note) return;

    document.getElementById("savedNotes").innerHTML += note + "<br>";
    document.getElementById("notes").value="";
}

// export campaign timeline
function exportTimeline(){
    const blob = new Blob([timeline.join("\\n")], {type:"text/plain"});
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "campaign_timeline.txt";
    link.click();
}

// export compliance report
function exportCompliance(){

    const report = `
LayerSeven Compliance Summary

MITRE Techniques Observed:
${Object.keys(mitreCounts).join("\\n")}

Cases Created: ${tickets.length}

Notes Logged: ${document.getElementById("savedNotes").innerText.length}
`;

    const blob = new Blob([report], {type:"text/plain"});
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "compliance_report.txt";
    link.click();
}

// load attacks
async function loadAttacks(){

    const paths = await fetch('/attack-paths').then(r=>r.json());

    const arcs = [];

    for(const p of paths){

        const tech = techniques[Math.floor(Math.random()*techniques.length)];

        updateMatrix(tech);
        createTicket(tech);

        timeline.push(new Date().toLocaleTimeString() + " — " + tech);

        arcs.push({
            startLat:p.from[0],
            startLng:p.from[1],
            endLat:p.to[0],
            endLng:p.to[1],
            color:"#ff0033",
            stroke:1.2
        });




    }

    globe.arcsData(arcs);
    




}

loadAttacks();
setInterval(loadAttacks, 3500);
</script>
</body>
</html>
"""






