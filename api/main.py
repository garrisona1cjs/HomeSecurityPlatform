# =========================================================
# IMPORTS
# =========================================================

import os
import asyncio

from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse

from .database import engine, Base
from .websocket_manager import connections
from .websocket_manager import broadcast
from .websocket_manager import event_queue
from .database import get_db
from sqlalchemy.orm import Session
from fastapi import Depends
from .models import Alert

# models
from .models import *

# routers will be added later if desired


# =========================================================
# FASTAPI APPLICATION
# =========================================================

app = FastAPI(
    title="LayerSeven Security Platform"
)


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
# STARTUP EVENTS
# =========================================================

@app.on_event("startup")
async def start_dispatcher():

    asyncio.create_task(event_dispatcher())


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

import os

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
            "severity": a.severity,
            "technique": a.technique,
            "latitude": a.latitude,
            "longitude": a.longitude,
            "country_code": a.country_code,
            "origin_label": a.origin_label,
            "timestamp": str(a.timestamp)
        })

    return results

# =========================================================
# SIMULATION TEST EVENT
# =========================================================

import random
import uuid
from datetime import datetime

@app.get("/simulate")
def simulate_attack():

    event = {
        "id": str(uuid.uuid4()),
        "severity": random.choice(["LOW","MEDIUM","HIGH","CRITICAL"]),
        "technique": "Simulation Attack",
        "latitude": random.uniform(-60, 60),
        "longitude": random.uniform(-180, 180),
        "country_code": "US",
        "origin_label": "Simulation",
        "timestamp": datetime.utcnow().isoformat()
    }

    event_queue.append(event)

    return {"status": "event generated"}


# =========================================================
# SERVER STARTUP (LOCAL RUN)
# =========================================================

if __name__ == "__main__":

    import uvicorn


    port = int(os.environ.get("PORT", 10000))

    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=port,
        reload=True
    )



    



















