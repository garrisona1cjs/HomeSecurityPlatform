from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from datetime import datetime
from typing import List
import uuid
import secrets

app = FastAPI(
    title="HomeSecurity Platform API",
    version="2.0.0"
)

registered_agents = {}
device_reports = []


class AgentRegistration(BaseModel):
    hostname: str
    ip_address: str


class DeviceReport(BaseModel):
    agent_id: str
    devices: List[dict]


def verify_agent(agent_id: str, x_api_key: str = Header(None)):
    if agent_id not in registered_agents:
        raise HTTPException(status_code=401, detail="Invalid agent")

    stored_key = registered_agents[agent_id]["api_key"]

    if x_api_key != stored_key:
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.post("/register")
def register_agent(agent: AgentRegistration):
    agent_id = str(uuid.uuid4())
    api_key = secrets.token_hex(32)

    registered_agents[agent_id] = {
        "hostname": agent.hostname,
        "ip_address": agent.ip_address,
        "api_key": api_key,
        "registered_at": datetime.utcnow().isoformat()
    }

    return {
        "agent_id": agent_id,
        "api_key": api_key,
        "message": "Agent registered successfully"
    }


@app.post("/report")
def report_devices(report: DeviceReport, x_api_key: str = Header(None)):
    verify_agent(report.agent_id, x_api_key)

    device_reports.append({
        "agent_id": report.agent_id,
        "devices": report.devices,
        "timestamp": datetime.utcnow().isoformat()
    })

    return {"message": "Report received"}


@app.get("/agents")
def get_agents():
    return registered_agents


@app.get("/reports")
def get_reports():
    return device_reports