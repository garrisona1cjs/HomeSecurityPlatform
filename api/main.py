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

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():

    with open("dashboard.html", "r", encoding="utf-8") as f:

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



    



















