# =========================================================
# IMPORTS
# =========================================================

import os
import asyncio



import random
import uuid
from datetime import datetime, timedelta

from fastapi import FastAPI, WebSocket, Depends
from fastapi.responses import HTMLResponse


from sqlalchemy.orm import Session

from .database import engine, Base, get_db
from .websocket_manager import connections, broadcast, event_queue
from .models import Alert, Incident









# =========================================================
# FASTAPI APPLICATION
# =========================================================

app = FastAPI(title="LayerSeven Security Platform")

from . import incidents

app.include_router(incidents.router)


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

Base.metadata.create_all(bind=engine)

from sqlalchemy import text

def update_incident_schema():

    with engine.connect() as conn:

        db_url = str(engine.url)

        # ======================================================
        # SQLITE MODE
        # ======================================================
        if "sqlite" in db_url:

            result = conn.execute(text("PRAGMA table_info(incidents)"))
            columns = [row[1] for row in result.fetchall()]

            def add_column(name, sql):
                if name not in columns:
                    conn.execute(text(sql))

        # ======================================================
        # POSTGRES MODE
        # ======================================================
        else:

            result = conn.execute(text("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = 'incidents'
            """))

            columns = [row[0] for row in result.fetchall()]

            def add_column(name, sql):
                if name not in columns:
                    conn.execute(text(sql))

        # ======================================================
        # COMMON COLUMN CREATION
        # ======================================================

        add_column("lat", "ALTER TABLE incidents ADD COLUMN lat FLOAT")
        add_column("lng", "ALTER TABLE incidents ADD COLUMN lng FLOAT")
        add_column("count", "ALTER TABLE incidents ADD COLUMN count INTEGER DEFAULT 1")
        add_column("risk", "ALTER TABLE incidents ADD COLUMN risk INTEGER DEFAULT 0")
        add_column("last_seen", "ALTER TABLE incidents ADD COLUMN last_seen DATETIME")

        add_column("status", "ALTER TABLE incidents ADD COLUMN status TEXT DEFAULT 'NEW'")
        add_column("assigned_to", "ALTER TABLE incidents ADD COLUMN assigned_to TEXT")
        add_column("priority", "ALTER TABLE incidents ADD COLUMN priority INTEGER DEFAULT 0")
        add_column("created_at", "ALTER TABLE incidents ADD COLUMN created_at DATETIME")
        add_column("updated_at", "ALTER TABLE incidents ADD COLUMN updated_at DATETIME")
        add_column("sla_deadline", "ALTER TABLE incidents ADD COLUMN sla_deadline DATETIME")

        add_column("escalation_level", "ALTER TABLE incidents ADD COLUMN escalation_level INTEGER DEFAULT 0")
        add_column("threat_type", "ALTER TABLE incidents ADD COLUMN threat_type TEXT")
        add_column("recommended_action", "ALTER TABLE incidents ADD COLUMN recommended_action TEXT")
        add_column("confidence", "ALTER TABLE incidents ADD COLUMN confidence FLOAT")

        add_column("mitre_id", "ALTER TABLE incidents ADD COLUMN mitre_id TEXT")
        add_column("mitre_tactic", "ALTER TABLE incidents ADD COLUMN mitre_tactic TEXT")

        conn.commit()




# =========================================================
# EVENT DISPATCHER
# =========================================================

QUEUE_FLUSH_INTERVAL = 0.2


async def event_dispatcher():

    while True:

        if event_queue:

            batch = event_queue.copy()

            event_queue.clear()

            await broadcast({
                "type": "batch",
                "events": batch
            })

        await asyncio.sleep(QUEUE_FLUSH_INTERVAL)

# =========================================================
# TECHNIQUE CLASSIFIER (MITRE MAPPING INPUT)
# =========================================================

def classify_technique(severity, country):

    # simple simulation logic (expand later)

    if severity == "CRITICAL":
        return "data_exfiltration"

    if severity == "HIGH":
        return random.choice([
            "brute_force",
            "command_and_control",
            "lateral_movement"
        ])

    if severity == "MEDIUM":
        return random.choice([
            "port_scan",
            "brute_force"
        ])

    return "port_scan"


# =========================================================
# BACKGROUND ATTACK GENERATOR
# =========================================================

async def attack_generator():

    botnet_centers = [
        ("CN", 35, 103),
        ("RU", 60, 90),
        ("IR", 32, 53),
        ("BR", -10, -55),
        ("US", 37, -95),
        ("DE", 51, 10)
    ]

    while True:

        # choose a botnet region
        country, base_lat, base_lon = random.choice(botnet_centers)

        # burst size (storm)
        burst = random.randint(6, 20)

        for _ in range(burst):

            severity = random.choices(
                ["LOW","MEDIUM","HIGH","CRITICAL"],
                weights=[50,30,15,5]
            )[0]

            lat = base_lat + random.uniform(-6,6)
            lon = base_lon + random.uniform(-6,6)

            event_id = str(uuid.uuid4())

            technique = classify_technique(severity, country)

            event = {
                "id": event_id,
                "severity": severity,
                "technique": technique,
                "latitude": lat,
                "longitude": lon,
                "country_code": country,
                "origin_label": f"Botnet Cluster ({country})",
                "timestamp": datetime.utcnow().isoformat(),
                "botnet_flag": "BOTNET_CLUSTER"
            }

            event_queue.append(event)

            await asyncio.sleep(random.uniform(0.2,0.8))

        # cooldown between storms
        await asyncio.sleep(random.uniform(6,12))

# =========================================================
# INTELLIGENCE ENGINE (GLOBAL)
# =========================================================

def analyze_incident(inc):

    threat = "unknown"
    action = "Monitor"
    confidence = 0.3
    mitre = "N/A"
    tactic = "Unknown"

    # =========================================
    # HIGH RISK = ACTIVE ATTACK
    # =========================================
    if inc.risk and inc.risk > 150:
        threat = "active_intrusion"
        action = "Isolate affected systems immediately"
        confidence = 0.9
        mitre = "T1041"
        tactic = "Exfiltration"

    # =========================================
    # HIGH VOLUME = RECON
    # =========================================
    elif inc.count and inc.count > 20:
        threat = "reconnaissance"
        action = "Block source IP / enable firewall rules"
        confidence = 0.75
        mitre = "T1046"
        tactic = "Discovery"

    # =========================================
    # MID RISK
    # =========================================
    elif inc.risk and inc.risk > 50:
        threat = "suspicious_activity"
        action = "Investigate logs and endpoint behavior"
        confidence = 0.6
        mitre = "T1071"
        tactic = "Command and Control"

    return threat, action, confidence, mitre, tactic

# =========================================================
# AUTO ESCALATION ENGINE (SLA ENFORCEMENT)
# =========================================================

async def escalation_engine():

    while True:

        await asyncio.sleep(5)

        db = next(get_db())

        try:

            now = datetime.utcnow()

            incidents = db.query(Incident).limit(50).all()

            for inc in incidents:

                if inc.status == "RESOLVED":
                    continue

                # (existing SLA logic...)

                # ======================================================
                # APPLY INTELLIGENCE
                # ======================================================

                threat, action, confidence, mitre, tactic = analyze_incident(inc)

                inc.threat_type = threat
                inc.recommended_action = action
                inc.confidence = confidence
                inc.mitre_id = mitre
                inc.mitre_tactic = tactic

                if inc.sla_deadline and now > inc.sla_deadline:

                    # MAX ESCALATION GUARD
                    if inc.escalation_level >= 3:
                        continue

                    inc.escalation_level += 1

                    # STATUS PROGRESSION
                    if inc.escalation_level == 1:
                        inc.status = "INVESTIGATING"

                    elif inc.escalation_level == 2:
                        inc.status = "CONTAINED"

                    elif inc.escalation_level == 3:
                        inc.status = "CRITICAL_RESPONSE"

                    # PRIORITY BOOST
                    inc.priority = min((inc.priority or 0) + 25, 100)

                    # NEW SLA WINDOW (SHORTER EACH LEVEL)
                    if inc.escalation_level == 1:
                        inc.sla_deadline = now + timedelta(seconds=60)

                    elif inc.escalation_level == 2:
                        inc.sla_deadline = now + timedelta(seconds=45)

                    else:
                        inc.sla_deadline = now + timedelta(seconds=30)

                    # ======================================================
                    # AUTO REASSIGN (SOC FAILSAFE)
                    # ======================================================

                    if inc.escalation_level >= 3:

                        # if nobody owns it → assign SOC
                        if not inc.assigned_to:
                            inc.assigned_to = "SOC-AUTO"

                        # if already owned but not resolved → mark as overdue
                        if inc.status != "RESOLVED":
                            inc.priority = min((inc.priority or 0) + 10, 100)

                            print(f"⚠️ SOC AUTO-INTERVENTION: {inc.id}")

                        print(f"🚨 ESCALATED L{inc.escalation_level}: {inc.id} → {inc.status}")
                    # ======================================================
                    # ANALYST INACTIVITY DETECTION
                    # ======================================================

                    if inc.assigned_to and inc.updated_at:

                        idle_time = (now - inc.updated_at).total_seconds()

                        if idle_time > 120:  # 2 minutes idle

                            inc.priority = min((inc.priority or 0) + 15, 100)

                            print(f"⏱️ INACTIVE ANALYST: {inc.assigned_to} on {inc.id}")

                    await asyncio.sleep(0.05)

                   

            db.commit()

        

        except Exception as e:
            db.rollback()
            print("ESCALATION ERROR:", e)

        finally:
            db.close()


# =========================================================
# STARTUP EVENTS
# =========================================================

@app.on_event("startup")
async def start_engines():

    update_incident_schema()   # only this
    update_incident_schema()

    await asyncio.sleep(1)

    asyncio.create_task(event_dispatcher())

    asyncio.create_task(attack_generator())

    asyncio.create_task(escalation_engine())


# =========================================================
# WEBSOCKET HUB
# =========================================================

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):

    await ws.accept()

    connections.add(ws)

    try:

        while True:

            await ws.receive_text()

    except:

        connections.discard(ws)




# =========================================================
# DASHBOARD
# =========================================================



@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():

    dashboard_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "dashboard",
        "dashboard.html"
    )

    with open(dashboard_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


# =========================================================
# ROOT
# =========================================================

@app.get("/")
def root():

    return {
        "platform": "LayerSeven Security Platform",
        "status": "online"
    }


# =========================================================
# ALERTS API
# =========================================================

@app.get("/alerts")
def get_alerts(db: Session = Depends(get_db)):

    from sqlalchemy import text

    try:

        result = db.execute(text("""
            SELECT severity,
            technique,
            latitude,
            longitude,
            country_code,
            origin_label,
            timestamp,
            status
        FROM alerts
            ORDER BY timestamp DESC
            LIMIT 500
        """))

        rows = result.fetchall()

        alerts = []

        for r in rows:

            alerts.append({
                "severity": r[0],
                "technique": r[1],
                "latitude": float(r[2]) if r[2] else 0,
                "longitude": float(r[3]) if r[3] else 0,
                "country_code": r[4],
                "origin_label": r[5],
                "timestamp": str(r[6]),
                "status": r[7] or "NEW"
            })

        return alerts

    except Exception as e:

        print("ALERT API ERROR:", e)

        return []
    
# =========================================================
# UPDATE ALERT STATUS (ACK / ESCALATE)
# =========================================================

@app.post("/alerts/update-status")
def update_alert_status(data: dict, db: Session = Depends(get_db)):

    try:

        alert_id = data.get("id")
        status = data.get("status")

        if not alert_id or not status:
            return {"error": "missing id or status"}

        from sqlalchemy import text

        db.execute(text("""
            UPDATE alerts
            SET status = :status
            WHERE id = :id
        """), {
            "id": alert_id,
            "status": status
        })

        db.commit()

        return {"status": "updated"}

    except Exception as e:
        db.rollback()
        return {"error": str(e)}
    
# =========================================================
# INCIDENT ENGINE
# =========================================================



def calculate_incident_priority(incident):
    """
    Priority scoring logic (0–100+)
    """

    score = 0

    # base risk
    score += incident.risk or 0

    # volume boost
    score += min(incident.count * 5, 50)

    # recency boost (fresh attacks = higher priority)
    if incident.last_seen:
        delta = datetime.utcnow() - incident.last_seen
        seconds = delta.total_seconds()

        if seconds < 60:
            score += 30
        elif seconds < 300:
            score += 15

    return score


def find_or_create_incident(db, lat, lon):

    now = datetime.utcnow()

    # 🔥 SAFE QUERY (IGNORE NULL COORDS)
    incident = db.query(Incident).filter(
        Incident.lat != None,
        Incident.lng != None,
        Incident.lat.between(lat - 2, lat + 2),
        Incident.lng.between(lon - 2, lon + 2),
        Incident.last_seen >= now - timedelta(seconds=60)
    ).first()

    # ======================================================
    # EXISTING INCIDENT
    # ======================================================

    if incident:
        incident.count += 1
        incident.last_seen = now


        incident.risk = (incident.risk or 0) + random.randint(5, 20)


        incident.priority = calculate_incident_priority(incident)


        threat, action, confidence = analyze_incident(incident)

        incident.threat_type = threat
        incident.recommended_action = action
        incident.confidence = confidence

        db.commit()
        return incident

    # ======================================================
    # NEW INCIDENT (FORCED)
    # ======================================================

    incident = Incident(
        id=str(uuid.uuid4()),
        lat=lat,
        lng=lon,
        count=1,
        risk=random.randint(10, 30),
        last_seen=now,
        status="NEW",
        priority=0,
        escalation_level=0,
        created_at=now,
        updated_at=now,
        sla_deadline=now + timedelta(seconds=60)
    )

    db.add(incident)
    db.commit()
    db.refresh(incident)

    # 🔥 APPLY INTELLIGENCE
    threat, action, confidence = analyze_incident(incident)

    incident.threat_type = threat
    incident.recommended_action = action
    incident.confidence = confidence

    db.commit()

    print("✅ INCIDENT CREATED:", incident.id)

    return incident




# =========================================================
# SIMULATION ENDPOINT
# =========================================================

@app.get("/simulate")
def simulate_attack(db: Session = Depends(get_db)):

    from sqlalchemy import text

    # -------------------------------------------------
    # DATABASE SCHEMA FIX (runs safely every time)
    # -------------------------------------------------

   


    # -------------------------------------------------
    # GENERATE SIMULATION EVENT
    # -------------------------------------------------

    severity = random.choice(["LOW","MEDIUM","HIGH","CRITICAL"])

    lat = random.uniform(-60, 60)
    lon = random.uniform(-180, 180)

    event_id = str(uuid.uuid4())

    technique = classify_technique(severity, "US")

    event = {
        "id": event_id,
        "severity": severity,
        "technique": technique,
        "latitude": lat,
        "longitude": lon,
        "country_code": "US",
        "origin_label": "Simulation",
        "timestamp": datetime.utcnow().isoformat()
    }

    # push event to websocket queue
    event_queue.append(event)


    # -------------------------------------------------
    # STORE ALERT IN DATABASE
    # -------------------------------------------------

    # ==================================================
    # INCIDENT LINKING
    # ==================================================

    incident = find_or_create_incident(db, lat, lon)

    try:

        from sqlalchemy import text

        try:

            db.execute(text("""
                    INSERT INTO alerts
                    (id, severity, technique, latitude, longitude, country_code, origin_label, timestamp, incident_id)
                    VALUES
                    (:id, :severity, :technique, :latitude, :longitude, :country_code, :origin_label, :timestamp, :incident_id)
                """), {
                    "id": event_id,
                    "incident_id": incident.id,
                    "severity": severity,
                    "technique": technique,
                    "latitude": lat,
                    "longitude": lon,
                    "country_code": "US",
                    "origin_label": "Simulation",
                    "timestamp": datetime.utcnow()
                })

            db.commit()

            print("ALERT STORED:", event_id)

        except Exception as e:

            db.rollback()

            print("DATABASE ERROR:", e)

            return {"status":"db_error","error":str(e)}


        print("ALERT STORED:", event_id)

    except Exception as e:

        db.rollback()

        print("DATABASE ERROR:", e)

        return {"status":"db_error","error":str(e)}

    return {"status":"event generated"}

# =========================================================
# INCIDENT API
# =========================================================

@app.get("/incidents")
def get_incidents(db: Session = Depends(get_db)):

    from sqlalchemy import text

    try:

        result = db.execute(text("""
            SELECT id,
                   lat,
                   lng,
                   count,
                   risk,
                   priority,
                   status,
                   sla_deadline,
                   last_seen,
                   threat_type,
                   recommended_action,
                   confidence,
                   escalation_level,
                   assigned_to
            FROM incidents
            ORDER BY priority DESC
            LIMIT 100
        """))

        rows = result.fetchall()

        incidents = []

        for r in rows:

            incidents.append({
                "id": r[0],
                "lat": r[1],
                "lng": r[2],
                "count": r[3],
                "risk": r[4],
                "priority": r[5],
                "status": r[6],
                "sla_deadline": r[7],
                "last_seen": r[8],
                "threat_type": r[9],
                "recommended_action": r[10],
                "confidence": r[11],
                "escalation_level": r[12],
                "assigned_to": r[13]
            })

        return incidents

    except Exception as e:
        print("INCIDENT API ERROR:", e)
        return []









    



















