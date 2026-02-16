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
# LayerSeven Enterprise Command Console
# -----------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
<!DOCTYPE html>
<html>
<head>
<title>LayerSeven Enterprise Command Console</title>

<script src="https://unpkg.com/globe.gl"></script>

<style>
body { margin:0; background:black; color:#00ffff; font-family:monospace; overflow:hidden;}

#globeViz { width:100vw; height:100vh; }

/* panels */
.panel {
    position:absolute;
    background:rgba(0,10,25,0.85);
    padding:10px;
    border-radius:6px;

}

#mitreGrid { left:10px; top:40px; width:280px; }
#tickets { right:10px; top:40px; width:280px; }
#roles { left:10px; bottom:10px; width:280px; }
#exec { right:10px; bottom:10px; width:280px; }

/* MITRE grid */
.grid {
    display:grid;
    grid-template-columns:repeat(2, 1fr);
    gap:4px;
    font-size:12px;
}

.cell {
    border:1px solid #00ffff55;
    padding:3px;
}

.active {
    background:#ff003355;
}

/* buttons */
button, select {
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

<div id="mitreGrid" class="panel">
<b>MITRE ATT&CK Matrix</b>
<div id="grid" class="grid"></div>
</div>

<div id="tickets" class="panel">
<b>Case Tickets</b><br>
<div id="ticketList"></div>
</div>

<div id="roles" class="panel">
<b>Access Role</b>
<select id="roleSelect" onchange="setRole()">
<option>Analyst</option>
<option>Lead</option>
<option>Admin</option>
</select>
<div id="roleStatus">Role: Analyst</div>
</div>

<div id="exec" class="panel">
<b>Executive Risk Dashboard</b><br>
Risk Score: <span id="riskScore">0</span><br>
Threat Actor: <span id="actor">Unknown</span><br>
Feed Insight: <span id="feed">None</span>
</div>

<script>
const globe = Globe()(document.getElementById('globeViz'))
  .globeImageUrl('//unpkg.com/three-globe/example/img/earth-dark.jpg');

globe.controls().autoRotate = true;

// MITRE techniques (matrix)
const techniques = [
"T1595 Active Scanning",
"T1110 Brute Force",
"T1046 Network Discovery",
"T1021 Remote Services",
"T1078 Valid Accounts",
"T1105 Exfiltration",
"T1059 Command Execution",
"T1087 Account Discovery"
];

let mitreHits = {};
let tickets = [];
let role = "Analyst";
let riskScore = 0;

// build matrix grid
function renderGrid(){
    const grid = document.getElementById("grid");
    grid.innerHTML = "";

    techniques.forEach(t=>{
        const div = document.createElement("div");
        div.className = "cell" + (mitreHits[t] ? " active" : "");
        div.innerHTML = t;
        grid.appendChild(div);
    });
}

// update MITRE
function updateTechnique(tech){
    mitreHits[tech] = true;
    renderGrid();
}

// ticket workflow
function createTicket(tech){
    const id = "CASE-" + Math.floor(Math.random()*9000);
    tickets.push({id:id, status:"OPEN", tech:tech});

    updateTicketDisplay();
}

function updateTicketDisplay(){
    const list = document.getElementById("ticketList");
    list.innerHTML = "";

    tickets.forEach(t=>{
        list.innerHTML += t.id + " — " + t.tech + " [" + t.status + "]<br>";
    });
}

// role control
function setRole(){
    role = document.getElementById("roleSelect").value;
    document.getElementById("roleStatus").innerHTML = "Role: " + role;
}

// threat actor attribution feed
function attributionFeed(){
    const actors = [
        "APT-style behavior",
        "Botnet campaign",
        "Credential harvesting group",
        "Commodity malware actor"
    ];

    const actor = actors[Math.floor(Math.random()*actors.length)];
    document.getElementById("actor").innerHTML = actor;
}

// external intelligence feed insight
function feedInsight(){
    const insights = [
        "Malicious ASN correlation",
        "Known C2 infrastructure match",
        "Tor exit node activity",
        "Cloud abuse pattern detected"
    ];

    document.getElementById("feed").innerHTML =
        insights[Math.floor(Math.random()*insights.length)];
}

// load attacks
async function loadAttacks(){

    const paths = await fetch('/attack-paths').then(r=>r.json());

    const arcs = [];

    for(const p of paths){

        const tech = techniques[Math.floor(Math.random()*techniques.length)];

        updateTechnique(tech);
        createTicket(tech);

        riskScore += 2;

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

    document.getElementById("riskScore").innerHTML = riskScore;

    attributionFeed();
    feedInsight();
}

renderGrid();
loadAttacks();
setInterval(loadAttacks, 3500);
</script>
</body>
</html>
"""






