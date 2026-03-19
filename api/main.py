# =========================================================
# IMPORTS
# =========================================================

import os
import asyncio



import random
import uuid
from datetime import datetime

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


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

Base.metadata.create_all(bind=engine)

from sqlalchemy import text

def update_alert_schema():

    with engine.connect() as conn:

        conn.execute(text("""
        ALTER TABLE alerts
        ADD COLUMN IF NOT EXISTS organization_id INTEGER
        """))

        conn.execute(text("""
        ALTER TABLE alerts
        ADD COLUMN IF NOT EXISTS risk_score INTEGER
        """))

        conn.execute(text("""
        ALTER TABLE alerts
        ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'NEW'
        """))

        # ✅ ADD THIS RIGHT HERE
        conn.execute(text("""
        ALTER TABLE alerts
        ADD COLUMN IF NOT EXISTS incident_id TEXT
        """))

        conn.commit()

update_alert_schema()


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
# STARTUP EVENTS
# =========================================================

@app.on_event("startup")
async def start_engines():

    asyncio.create_task(event_dispatcher())

    asyncio.create_task(attack_generator())


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
                timestamp
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

from datetime import timedelta

def find_or_create_incident(db, lat, lon):

    now = datetime.utcnow()

    incident = db.query(Incident).filter(
        Incident.latitude.between(lat - 2, lat + 2),
        Incident.longitude.between(lon - 2, lon + 2),
        Incident.last_seen >= now - timedelta(seconds=60)
    ).first()

    if incident:
        incident.event_count += 1
        incident.last_seen = now
        return incident

    # create new incident
    incident = Incident(
        id=str(uuid.uuid4()),
        latitude=lat,
        longitude=lon,
        event_count=1,
        risk_score=0,
        first_seen=now,
        last_seen=now
    )

    db.add(incident)
    db.commit()
    db.refresh(incident)

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

    try:

        with engine.connect() as conn:

            conn.execute(text("""
            ALTER TABLE alerts
            ALTER COLUMN latitude TYPE DOUBLE PRECISION
            USING latitude::double precision
            """))

            conn.execute(text("""
            ALTER TABLE alerts
            ALTER COLUMN longitude TYPE DOUBLE PRECISION
            USING longitude::double precision
            """))

            conn.commit()

    except Exception as e:

        print("Schema already correct or skipped:", e)


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

    incidents = db.query(Incident).order_by(
        Incident.last_seen.desc()
    ).limit(100).all()

    return [
        {
            "id": i.id,
            "lat": i.latitude,
            "lng": i.longitude,
            "count": i.event_count,
            "risk": i.risk_score,
            "last_seen": i.last_seen
        }
        for i in incidents
    ]









    



















