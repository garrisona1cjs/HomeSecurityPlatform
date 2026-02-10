from datetime import datetime, timezone
from pathlib import Path
import json

KNOWN_DEVICES_FILE = Path("known_devices.json")
INCIDENT_COUNTER_FILE = Path(".incident_counter")


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def load_devices():
    if not KNOWN_DEVICES_FILE.exists():
        return {}
    return json.loads(KNOWN_DEVICES_FILE.read_text())


def save_devices(data):
    KNOWN_DEVICES_FILE.write_text(json.dumps(data, indent=2))


def next_incident_id() -> str:
    if not INCIDENT_COUNTER_FILE.exists():
        INCIDENT_COUNTER_FILE.write_text("1")

    counter = int(INCIDENT_COUNTER_FILE.read_text())
    INCIDENT_COUNTER_FILE.write_text(str(counter + 1))

    year = datetime.now(timezone.utc).year
    return f"INC-{year}-{counter:04d}"


def open_incident(ip: str, severity: str, reason: str):
    devices = load_devices()
    device = devices.get(ip)

    if not device:
        return

    incident = device.get("incident")

    # Do not reopen if already open
    if incident and incident.get("status") == "OPEN":
        return

    device["incident"] = {
        "id": next_incident_id(),
        "status": "OPEN",
        "severity": severity,
        "reason": reason,
        "opened_at": now_iso(),
        "closed_at": None,
    }

    save_devices(devices)


def close_incident(ip: str, reason: str):
    devices = load_devices()
    device = devices.get(ip)

    if not device:
        return

    incident = device.get("incident")
    if not incident or incident.get("status") != "OPEN":
        return

    incident["status"] = "CLOSED"
    incident["closed_at"] = now_iso()
    incident["closure_reason"] = reason

    save_devices(devices)
    