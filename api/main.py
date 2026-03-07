# =========================================================
# IMPORTS
# =========================================================

from fastapi import FastAPI, Header, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import List
import uuid, secrets, os, random, asyncio
import geoip2.database

from sqlalchemy import create_engine, Column, String, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

from ipwhois import IPWhois


# =========================================================
# GEOIP CONFIG
# =========================================================

GEOIP_DB = os.getenv("GEOIP_DB", "geoip/GeoLite2-City.mmdb")

reader = None
if os.path.exists(GEOIP_DB):
    reader = geoip2.database.Reader(GEOIP_DB)


def geo_lookup_ip(ip):

    try:
        if reader:
            geo = reader.city(ip)
        else:
            raise Exception()

        city = geo.city.name or "Unknown"
        country = geo.country.iso_code or "??"
        lat = geo.location.latitude or 0
        lon = geo.location.longitude or 0

        origin_label = f"{city}, {country}"

    except:
        origin_label, lat, lon, country = "Unknown", 0, 0, "??"


    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1)

        asn = res.get("asn", "N/A")
        isp = res.get("network", {}).get("name", "Unknown")

    except:
        asn = "N/A"
        isp = "Unknown"

    return origin_label, lat, lon, country, isp, asn


# =========================================================
# DATABASE CONFIG
# =========================================================

DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10
)

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


# =========================================================
# INCIDENT MODEL
# =========================================================

class Incident(Base):

    __tablename__ = "incidents"

    id = Column(String, primary_key=True)
    source_ip = Column(String)
    asn = Column(String)
    country_code = Column(String)

    severity = Column(String)

    alert_count = Column(String)

    status = Column(String)

    first_seen = Column(String)
    last_seen = Column(String)


# =========================================================
# SAFE SCHEMA UPDATE
# =========================================================

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
# INCIDENT CORRELATION ENGINE
# =========================================================

CORRELATION_WINDOW = 120


def correlate_incident(db, source_ip, asn, country_code, severity):

    now = datetime.utcnow()


    incident = db.query(Incident).filter(
        Incident.source_ip == source_ip,
        Incident.asn == asn
    ).first()

    if incident:

        incident.alert_count = str(int(incident.alert_count) + 1)
        incident.last_seen = now.isoformat()

        db.commit()
        return incident

    incident = Incident(
        id=str(uuid.uuid4()),
        source_ip=source_ip,
        asn=asn,
        country_code=country_code,
        severity=severity,
        alert_count="1",
        status="NEW",
        first_seen=now.isoformat(),
        last_seen=now.isoformat()
    )

    db.add(incident)
    db.commit()

    return incident



# =========================================================
# THREAT CAMPAIGN DETECTION
# =========================================================

campaign_tracker = {
    "asn_activity": {},
    "country_activity": {},
    "ip_activity": {},
}

CAMPAIGN_WINDOW = 60
BOTNET_THRESHOLD = 6
ASN_ATTACK_THRESHOLD = 4
COUNTRY_CAMPAIGN_THRESHOLD = 5


def detect_campaign(source_ip, asn, country):

    now = datetime.utcnow().timestamp()


    campaign_tracker["ip_activity"].setdefault(source_ip, []).append(now)
    campaign_tracker["asn_activity"].setdefault(asn, []).append(now)
    campaign_tracker["country_activity"].setdefault(country, []).append(now)


    for category in campaign_tracker.values():

        for key in list(category.keys()):

            category[key] = [t for t in category[key] if now - t < CAMPAIGN_WINDOW]

            if not category[key]:
                del category[key]

    if source_ip in campaign_tracker["ip_activity"] and \
       len(campaign_tracker["ip_activity"][source_ip]) >= BOTNET_THRESHOLD:
        return "BOTNET_RECON_WAVE"

    if asn in campaign_tracker["asn_activity"] and \
       len(campaign_tracker["asn_activity"][asn]) >= ASN_ATTACK_THRESHOLD:
        return "ASN_COORDINATED_ATTACK"

    if country in campaign_tracker["country_activity"] and \
       len(campaign_tracker["country_activity"][country]) >= COUNTRY_CAMPAIGN_THRESHOLD:
        return "MULTI_ORIGIN_CAMPAIGN"

    return None







# =========================================================
# SURGE DETECTION
# =========================================================

recent_alerts = []

SURGE_WINDOW = 10
SURGE_THRESHOLD = 20


def detect_surge():

    now = datetime.utcnow()

    while recent_alerts and now - recent_alerts[0] > timedelta(seconds=SURGE_WINDOW):
        recent_alerts.pop(0)

    return len(recent_alerts) >= SURGE_THRESHOLD


# =========================================================
# WEBSOCKET HUB
# =========================================================

connections = set()

MAX_WS_CONNECTIONS = 50


async def broadcast(payload):

    dead = []

    for ws in connections:

        try:
            await ws.send_json(payload)

        except:
            dead.append(ws)

    for ws in dead:
        connections.remove(ws)


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):

    if len(connections) > MAX_WS_CONNECTIONS:
        await ws.close()
        return

    await ws.accept()

    connections.add(ws)

    try:

        while True:
            await ws.receive_text()

    except WebSocketDisconnect:

        connections.remove(ws)


# =========================================================
# REGISTER
# =========================================================

@app.post("/register")
def register(agent: AgentRegistration):

    return {
        "agent_id": str(uuid.uuid4()),
        "api_key": secrets.token_hex(16)
    }


# =========================================================
# REPORT DEVICES
# =========================================================

@app.post("/report")
async def report_devices(report: DeviceReport, x_api_key: str = Header(None)):

    if len(report.devices) > 50:
        raise HTTPException(status_code=400, detail="Too many devices reported")

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

    origin_label, lat, lon, country, isp_name, asn = geo_lookup_ip(ip_addr)

    campaign = detect_campaign(ip_addr, asn, country)

    technique = random.choice([
        "T1110 Brute Force",
        "T1078 Valid Accounts",
        "T1046 Network Scan",
        "T1059 Command Exec",
        "T1566 Phishing"
    ])

    shockwave_flag = severity == "CRITICAL"

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
        shockwave=str(shockwave_flag)
    )

    db.add(alert)
    db.commit()

    correlate_incident(db, ip_addr, asn, country, severity)

    db.close()


    recent_alerts.append(datetime.utcnow())
    surge = detect_surge()

    payload = {
        "severity": severity,
        "technique": technique,
        "origin_label": origin_label,
        "campaign": campaign,
        "latitude": lat,
        "longitude": lon,
        "country_code": country,
        "source_ip": ip_addr,
        "isp": isp_name,
        "asn": asn,
        "shockwave": shockwave_flag,
        "training": False,
        "team": "red",
        "surge": surge
    }

    await broadcast(payload)

    return {"risk_score": risk, "severity": severity}





# =========================================================
# ALERT HISTORY
# =========================================================

@app.get("/alerts")
def alerts():

    db = SessionLocal()

    data = db.query(Alert).order_by(Alert.timestamp.desc()).all()

    db.close()

    return data




# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
def health():
    return {"status": "ok"}
















