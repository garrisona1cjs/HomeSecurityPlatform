from datetime import datetime, timezone
from pathlib import Path
import json

KNOWN_DEVICES_FILE = Path("known_devices.json")
DECAY_PER_DAY = 5


def now_utc():
    return datetime.now(timezone.utc)


def load_devices() -> dict:
    if not KNOWN_DEVICES_FILE.exists():
        return {}
    return json.loads(KNOWN_DEVICES_FILE.read_text())


def save_devices(devices: dict):
    KNOWN_DEVICES_FILE.write_text(json.dumps(devices, indent=2))


def days_since(ts: str) -> int:
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (now_utc() - dt).days


def apply_risk_decay():
    devices = load_devices()
    changed = False

    for d in devices.values():
        last_update = d.get("last_risk_update")
        if not last_update:
            d["last_risk_update"] = now_utc().isoformat()
            continue

        elapsed_days = days_since(last_update)
        if elapsed_days <= 0:
            continue

        current_risk = d.get("risk_score", 0)
        decay_amount = elapsed_days * DECAY_PER_DAY
        new_risk = max(0, current_risk - decay_amount)

        if new_risk != current_risk:
            d["risk_score"] = new_risk
            d["last_risk_update"] = now_utc().isoformat()
            changed = True

    if changed:
        save_devices(devices)
