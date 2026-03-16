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

    while True:

        severity = random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"])

        lat = random.uniform(-60, 60)
        lon = random.uniform(-180, 180)

        event_id = str(uuid.uuid4())

        event = {
            "id": event_id,
            "severity": severity,
            "technique": "Automated Attack",
            "latitude": lat,
            "longitude": lon,
            "country_code": "US",
            "origin_label": "Autonomous Threat Engine",
            "timestamp": datetime.utcnow().isoformat()
        }

        event_queue.append(event)

        await asyncio.sleep(random.uniform(2,5))


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

    alerts = db.query(Alert).order_by(
        Alert.timestamp.desc()
    ).limit(500).all()

    results = []

    for a in alerts:

        results.append({

            "severity": a.severity or "LOW",
            "technique": a.technique or "Unknown",

            "latitude": float(a.latitude) if a.latitude else 0,
            "longitude": float(a.longitude) if a.longitude else 0,

            "country_code": a.country_code or "??",
            "origin_label": a.origin_label or "Unknown",

            "timestamp": a.timestamp.isoformat() if a.timestamp else ""
        })

    return results


# =========================================================
# SIMULATION ENDPOINT
# =========================================================

@app.get("/simulate")
def simulate_attack(db: Session = Depends(get_db)):

    severity = random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"])

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


    event_queue.append(event)



    alert = Alert(
        id=event_id,
        severity=severity,
        technique="Simulation Attack",
        latitude=lat,
        longitude=lon,
        country_code="US",
        origin_label="Simulation",
        timestamp=datetime.utcnow()
    )

    db.add(alert)
    db.commit()






    return {"status": "event generated"}









    



















