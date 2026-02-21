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
import geoip2.database

from sqlalchemy import create_engine, Column, String, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

# =========================================================
# GEOIP CONFIG
# =========================================================

GEOIP_DB = os.getenv("GEOIP_DB", "geoip/GeoLite2-City.mmdb")

def geo_lookup_ip(ip):
    try:
        with geoip2.database.Reader(GEOIP_DB) as reader:
            r = reader.city(ip)

            lat = r.location.latitude
            lon = r.location.longitude
            country = r.country.iso_code
            city = r.city.name
            country_name = r.country.name


            if lat is None or lon is None:
                return ("Unknown Location", 0, 0, country or "")

            label = f"{city}, {country_name}" if city else country_name
            return (label, lat, lon, country or "")

    except Exception:
        return ("Unknown Location", 0, 0, "")

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


    origin_label = Column(String)
    latitude = Column(String)
    longitude = Column(String)
    country_code = Column(String)
    shockwave = Column(String)

# ---- SAFE AUTO COLUMN ADD ----

inspector = inspect(engine)

if "alerts" in inspector.get_table_names():
    existing = [c["name"] for c in inspector.get_columns("alerts")]

    with engine.connect() as conn:
        if "origin_label" not in existing:
            conn.execute(text("ALTER TABLE alerts ADD COLUMN origin_label VARCHAR"))
        if "latitude" not in existing:
            conn.execute(text("ALTER TABLE alerts ADD COLUMN latitude VARCHAR"))
        if "longitude" not in existing:
            conn.execute(text("ALTER TABLE alerts ADD COLUMN longitude VARCHAR"))
        if "country_code" not in existing:
            conn.execute(text("ALTER TABLE alerts ADD COLUMN country_code VARCHAR"))
        if "shockwave" not in existing:
            conn.execute(text("ALTER TABLE alerts ADD COLUMN shockwave VARCHAR"))

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
# MITRE TECHNIQUES (SIMULATION)
# =========================================================

techniques = [
    "T1110 Brute Force",
    "T1078 Valid Accounts",
    "T1046 Network Scannin",
    "T1059 Command Exec",
    "T1566 Phishing"
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

async def broadcast(payload):
    dead = []
    for ws in connections:
        try:
            await ws.send_json(payload)
        except:
            dead.append(ws)
    for ws in dead:
        connections.remove(ws)

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


    ip_addr = report.devices[0].get("ip", "8.8.8.8")
    origin_label, lat, lon, country = geo_lookup_ip(ip_addr)

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
        country_code=country,
        shockwave=shockwave_flag
    )

    db.add(alert)
    db.commit()
    db.close()

    # broadcast live alert
    payload = {
        "severity": severity,
        "technique": technique,
        "origin_label": origin_label,
        "latitude": lat,
        "longitude": lon,
        "country_code": country,
        "shockwave": shockwave_flag == "true"
    }

    asyncio.create_task(broadcast(payload))

    return {"risk_score": risk, "severity": severity}

@app.get("/alerts")
def alerts():
    db = SessionLocal()
    data = db.query(Alert).order_by(Alert.timestamp.desc()).all()
    db.close()
    return data

@app.get("/attack-paths")
def attack_paths():
    return []

# =========================================================
# DASHBOARD
# =========================================================

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return open("static/dashboard.html", encoding="utf-8").read()
















