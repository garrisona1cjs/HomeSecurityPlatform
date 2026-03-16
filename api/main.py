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

    try:

        alerts = db.query(Alert).order_by(
            Alert.timestamp.desc()
        ).limit(500).all()

        results = []

        for a in alerts:

            results.append({
                "severity": getattr(a, "severity", "LOW"),
                "technique": getattr(a, "technique", "Unknown"),

                "latitude": float(a.latitude) if getattr(a, "latitude", None) else 0,
                "longitude": float(a.longitude) if getattr(a, "longitude", None) else 0,

                "country_code": getattr(a, "country_code", "??"),
                "origin_label": getattr(a, "origin_label", "Unknown"),

                "timestamp": a.timestamp.isoformat() if getattr(a, "timestamp", None) else ""
            })

        return results

    except Exception as e:

        print("ALERT API ERROR:", str(e))

        return []


# =========================================================
# SIMULATION ENDPOINT
# =========================================================

@app.get("/simulate")
def simulate_attack(db: Session = Depends(get_db)):

    try:

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

        # send to websocket
        event_queue.append(event)

        # store in database
        alert = Alert()

        alert.id = event_id
        alert.severity = severity
        alert.technique = "Simulation Attack"

        alert.latitude = lat
        alert.longitude = lon

        alert.country_code = "US"
        alert.origin_label = "Simulation"

        alert.timestamp = datetime.utcnow()

        db.add(alert)
        db.commit()

        return {"status": "event generated"}

    except Exception as e:

        print("SIMULATE ERROR:", str(e))

        return {
            "status": "error",
            "message": str(e)
        }









    



















