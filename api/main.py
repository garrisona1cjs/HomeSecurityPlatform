from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from datetime import datetime
from typing import List
import uuid
import os

app = FastAPI(
    title="HomeSecurity Platform API",
    version="1.0.0"
)

# 🔐 Load API key from environment variable
API_KEY = os.getenv("API_KEY")

registered_agents = {}
device_reports = []


class AgentRegistration(BaseModel):
    hostname: str
    ip_address: str


class DeviceReport(BaseModel):
    agent_id: str
    devices: List[dict]


def verify_api_key(x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/")
def root():
    return {"status": "HomeSecurityPlatform online"}


@app.post("/register")
def register_agent(agent: AgentRegistration, x_api_key: str = Header(None)):
    verify_api_key(x_api_key)

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


@app.post("/report")
def report_devices(report: DeviceReport, x_api_key: str = Header(None)):
    verify_api_key(x_api_key)

    device_reports.append({
        "agent_id": report.agent_id,
        "devices": report.devices,
        "timestamp": datetime.utcnow().isoformat()
    })

    return {"message": "Report received"}


@app.get("/agents")
def get_agents(x_api_key: str = Header(None)):
    verify_api_key(x_api_key)
    return registered_agents


@app.get("/reports")
def get_reports(x_api_key: str = Header(None)):
    verify_api_key(x_api_key)
    return device_reports