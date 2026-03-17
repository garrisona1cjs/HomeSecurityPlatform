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
from .models import Alert









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

            event = {
                "id": event_id,
                "severity": severity,
                "technique": "Botnet Storm",
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
                "timestamp": str(r[6])
            })

        return alerts

    except Exception as e:

        print("ALERT API ERROR:", e)

        return []


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

    event = {
        "id": event_id,
        "severity": severity,
        "technique": "Simulation Attack",
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

    try:

        from sqlalchemy import text

        try:

            db.execute(text("""
                    INSERT INTO alerts
                    (id, severity, technique, latitude, longitude, country_code, origin_label, timestamp)
                    VALUES
                    (:id, :severity, :technique, :latitude, :longitude, :country_code, :origin_label, :timestamp)
                """), {
                    "id": event_id,
                    "severity": severity,
                    "technique": "Simulation Attack",
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









    



















