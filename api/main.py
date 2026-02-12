from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
from typing import List
import uuid

app = FastAPI(
    title="HomeSecurity Platform API",
    version="1.0.0"
)

# ----------------------------
# In-memory storage (Phase 1)
# ----------------------------
registered_agents = {}
device_reports = []


# ----------------------------
# Models
# ----------------------------
class AgentRegistration(BaseModel):
    hostname: str
    ip_address: str


class DeviceReport(BaseModel):
    agent_id: str
    devices: List[dict]


# ----------------------------
# Root
# ----------------------------
@app.get("/")
def root():
    return {"status": "HomeSecurityPlatform online"}


# ----------------------------
# Agent Registration
# ----------------------------
@app.post("/register")
def register_agent(agent: AgentRegistration):
    agent_id = str(uuid.uuid4())

    registered_agents[agent_id] = {
        "hostname": agent.hostname,
        "ip_address": agent.ip_address,
        "registered_at": datetime.utcnow().isoformat()
    }

    return {
        "agent_id": agent_id,
        "message": "Agent registered successfully"
    }


# ----------------------------
# Device Reporting
# ----------------------------
@app.post("/report")
def report_devices(report: DeviceReport):
    device_reports.append({
        "agent_id": report.agent_id,
        "devices": report.devices,
        "timestamp": datetime.utcnow().isoformat()
    })

    return {"message": "Report received"}


# ----------------------------
# Admin Endpoints
# ----------------------------
@app.get("/agents")
def get_agents():
    return registered_agents


@app.get("/reports")
def get_reports():
    return device_reports
