from fastapi import FastAPI, Header, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from datetime import datetime
from typing import List
import uuid
import secrets
import os
import random
import asyncio

from sqlalchemy import create_engine, Column, String, inspect
from sqlalchemy.orm import declarative_base, sessionmaker

# =========================================================
# DATABASE CONFIG
# =========================================================

DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# =========================================================
# FASTAPI APP
# =========================================================


app = FastAPI(title="LayerSeven Security Platform")






app.mount("/static", StaticFiles(directory="static"), name="static")

# =========================================================
# DATABASE MODEL
# =========================================================

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True)
    agent_id = Column(String)
    risk_score = Column(String)
    severity = Column(String)
    technique = Column(String)
    timestamp = Column(String)

    # 🌍 origin info
    origin_label = Column(String)
    latitude = Column(String)
    longitude = Column(String)

    # 🔥 critical pulse flag
    shockwave = Column(String)

# ---- Safe schema update ----

inspector = inspect(engine)

if "alerts" in inspector.get_table_names():
    existing_cols = [c["name"] for c in inspector.get_columns("alerts")]

    required_cols = {
        "origin_label",
        "latitude",
        "longitude",
        "shockwave"
    }

    if not required_cols.issubset(existing_cols):
        Alert.__table__.drop(engine)

Base.metadata.create_all(bind=engine)

# =========================================================
# DATA SCHEMAS
# =========================================================

class AgentRegistration(BaseModel):
    hostname: str
    ip_address: str

class DeviceReport(BaseModel):
    agent_id: str
    devices: List[dict]

# =========================================================
# MOCK GEOLOCATION
# =========================================================

def geo_lookup():
    locations = [
        ("Tokyo, Japan", 35.68, 139.69),
        ("London, UK", 51.50, -0.12),
        ("São Paulo, Brazil", -23.55, -46.63),
        ("Berlin, Germany", 52.52, 13.40),
        ("Toronto, Canada", 43.65, -79.38),
        ("Sydney, Australia", -33.86, 151.20),
        ("San Francisco, USA", 37.77, -122.41),
        ("Des Moines, USA", 41.59, -93.62),
    ]
    return random.choice(locations)

# =========================================================
# MITRE TECHNIQUES (simulation)
# =========================================================

techniques = [
    "T1110 Brute Force",
    "T1078 Valid Accounts",
    "T1046 Network Scannin",
    "T1059 Command Exec",
    "T1566 Phishing"
]

# =========================================================
# API ROUTES
# =========================================================

@app.post("/register")
def register(agent: AgentRegistration):
    return {
        "agent_id": str(uuid.uuid4()),
        "api_key": secrets.token_hex(16)
    }

@app.post("/report")
def report_devices(report: DeviceReport, x_api_key: str = Header(None)):
    db = SessionLocal()


    risk = len(report.devices) * 40

    if risk >= 120:
        severity = "CRITICAL"
    elif risk >= 80:
        severity = "HIGH"
    elif risk >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    origin_label, lat, lon = geo_lookup()

    shockwave_flag = "true" if severity == "CRITICAL" else "false"

    technique = random.choice(techniques)

    alert = Alert(
        id=str(uuid.uuid4()),
        agent_id=report.agent_id,
        risk_score=str(risk),
        severity=severity,
        technique=technique,
        timestamp=datetime.utcnow().isoformat(),
        origin_label=origin_label,
        latitude=str(lat),
        longitude=str(lon),
        shockwave=shockwave_flag
    )

    db.add(alert)
    db.commit()
    db.close()

    # =========================
    # REAL-TIME BROADCAST
    # =========================
    payload = {
        "severity": severity,
        "technique": technique,
        "origin_label": origin_label,
        "latitude": lat,
        "longitude": lon,
        "shockwave": shockwave_flag == "true"
    }

    for ws in connections.copy():
        try:
            asyncio.create_task(ws.send_json(payload))
        except:
            pass

    return {"risk_score": risk, "severity": severity}




@app.get("/alerts")
def alerts():
    db = SessionLocal()
    data = db.query(Alert).order_by(Alert.timestamp.desc()).all()
    db.close()
    return data

@app.get("/attack-paths")
def attack_paths():

    return [
        {"from":[55.75,37.61], "to":[41.59,-93.62]},
        {"from":[35.68,139.69], "to":[41.59,-93.62]},
        {"from":[51.50,-0.12], "to":[41.59,-93.62]},
        {"from":[-23.55,-46.63], "to":[41.59,-93.62]},
        {"from":[37.77,-122.41], "to":[41.59,-93.62]}
    ]

# =========================================================
# WEBSOCKET HUB
# =========================================================

connections = set()

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    connections.add(ws)
    


    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        connections.remove(ws)

# =========================================================
# DASHBOARD ROUTE
# =========================================================

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    with open("static/dashboard.html", encoding="utf-8") as f:
        return f.read()

# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
def health():
    return {"status": "ok"}






