from sqlalchemy import Column, String, Integer, Float, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime

from .database import Base


# =========================================================
# ALERTS
# =========================================================

class Alert(Base):

    __tablename__ = "alerts"

    id = Column(String, primary_key=True)
    incident_id = Column(String, nullable=True)

    agent_id = Column(String)
    organization_id = Column(Integer)

    risk_score = Column(Integer)
    severity = Column(String)
    technique = Column(String)

    timestamp = Column(DateTime)

    origin_label = Column(String)
    latitude = Column(Float)
    longitude = Column(Float)

    country_code = Column(String)
    shockwave = Column(String)

# ======================================================
# INCIDENT MODEL (CLUSTER / CAMPAIGN)
# ======================================================

from sqlalchemy import Column, String, Integer, DateTime
from datetime import datetime

class Incident(Base):
    __tablename__ = "incidents"
    

    id = Column(String, primary_key=True)
    lat = Column(Float)
    lng = Column(Float)

    count = Column(Integer, default=1)
    risk = Column(Integer, default=0)

    last_seen = Column(DateTime)

    # ======================================================
    # INCIDENT WORKFLOW FIELDS (PHASE 9)
    # ======================================================
    status = Column(String, default="NEW")
    assigned_to = Column(String, nullable=True)
    priority = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

   


# =========================================================
# AGENTS
# =========================================================

class Agent(Base):

    __tablename__ = "agents"

    agent_id = Column(String, primary_key=True)

    hostname = Column(String)
    ip_address = Column(String)

    api_key = Column(String)
    agent_secret = Column(String)

    organization_id = Column(Integer)

    created_at = Column(DateTime, default=datetime.utcnow)

    last_heartbeat = Column(DateTime)
    status = Column(String)

    agent_version = Column(String)
    agent_uptime = Column(Integer)
    agent_hash = Column(String)

    tamper_flag = Column(String)
    tamper_count = Column(Integer)


# =========================================================
# ORGANIZATIONS
# =========================================================

class Organization(Base):

    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True)

    name = Column(String)

    created_at = Column(DateTime, default=datetime.utcnow)


# =========================================================
# USERS
# =========================================================

class User(Base):

    __tablename__ = "users"

    id = Column(Integer, primary_key=True)

    username = Column(String)
    email = Column(String)

    password_hash = Column(String)

    role = Column(String)

    organization_id = Column(Integer)

    created_at = Column(DateTime, default=datetime.utcnow)


# =========================================================
# ENROLLMENT TOKENS
# =========================================================

class EnrollmentToken(Base):

    __tablename__ = "enrollment_tokens"

    id = Column(String, primary_key=True)

    organization_id = Column(
        Integer,
        ForeignKey("organizations.id")
    )

    token = Column(String)

    created_at = Column(DateTime, default=datetime.utcnow)

    expires_at = Column(DateTime)

    revoked = Column(Boolean)

    organization = relationship("Organization")


# =========================================================
# INCIDENT CORRELATION
# =========================================================

class Incident(Base):

    __tablename__ = "incidents"

    id = Column(String, primary_key=True)

    source_ip = Column(String)
    asn = Column(String)
    country_code = Column(String)

    severity = Column(String)

    alert_count = Column(Integer)

    status = Column(String)

    first_seen = Column(DateTime)
    last_seen = Column(DateTime)


# =========================================================
# SOC COMMAND AUDIT
# =========================================================

class CommandAudit(Base):

    __tablename__ = "command_audit"

    id = Column(String, primary_key=True)

    user_id = Column(Integer)

    agent_id = Column(String)

    command = Column(String)

    timestamp = Column(DateTime, default=datetime.utcnow)


# =========================================================
# AGENT TASKS
# =========================================================

class AgentTask(Base):

    __tablename__ = "agent_tasks"

    id = Column(String, primary_key=True)

    agent_id = Column(String)

    command = Column(String)

    status = Column(String)

    created_at = Column(DateTime, default=datetime.utcnow)

    completed_at = Column(DateTime)

    result = Column(String)


# =========================================================
# THREAT INFRASTRUCTURE INTEL
# =========================================================

class ThreatInfrastructure(Base):

    __tablename__ = "threat_infrastructure"

    id = Column(Integer, primary_key=True)

    ip_address = Column(String)

    asn = Column(String)

    country = Column(String)

    attack_count = Column(Integer)

    first_seen = Column(DateTime, default=datetime.utcnow)

    last_seen = Column(DateTime, default=datetime.utcnow)

    avg_threat_score = Column(Float)

    campaign = Column(String)