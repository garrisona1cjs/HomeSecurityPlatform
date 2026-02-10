from datetime import datetime, timezone
from pathlib import Path
import json

KNOWN_DEVICES_FILE = Path("known_devices.json")


def today_utc() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def load_devices():
    if not KNOWN_DEVICES_FILE.exists():
        return {}
    return json.loads(KNOWN_DEVICES_FILE.read_text())


def save_devices(data):
    KNOWN_DEVICES_FILE.write_text(json.dumps(data, indent=2))


def record_risk_snapshot(ip: str, risk_score: int):
    devices = load_devices()
    device = devices.get(ip)

    if not device:
        return

    device.setdefault("risk_history", [])

    today = today_utc()

    # Overwrite today's entry if it exists
    for entry in device["risk_history"]:
        if entry["date"] == today:
            entry["risk_score"] = risk_score
            save_devices(devices)
            return

    # Otherwise append new day
    device["risk_history"].append({
        "date": today,
        "risk_score": risk_score,
    })

    save_devices(devices)
    