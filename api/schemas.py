from pydantic import BaseModel
from typing import List


# =========================================================
# AGENT REGISTRATION
# =========================================================

class AgentRegistration(BaseModel):

    hostname: str
    ip_address: str
    enrollment_token: str


# =========================================================
# DEVICE REPORT
# =========================================================

class DeviceReport(BaseModel):

    agent_id: str
    devices: List[dict]


# =========================================================
# AGENT HEARTBEAT
# =========================================================

class AgentHeartbeat(BaseModel):

    agent_id: str
    agent_version: str
    agent_uptime: int
    agent_hash: str


# =========================================================
# ORGANIZATION
# =========================================================

class OrganizationCreate(BaseModel):

    name: str


# =========================================================
# SOC TASKS
# =========================================================

class AgentTaskCreate(BaseModel):

    agent_id: str
    command: str


class AgentTaskResult(BaseModel):

    task_id: str
    result: str


# =========================================================
# USER AUTH
# =========================================================

class RegisterRequest(BaseModel):

    username: str
    email: str
    password: str
    organization_id: int


class LoginRequest(BaseModel):

    username: str
    password: str