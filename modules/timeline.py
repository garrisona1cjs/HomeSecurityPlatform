from datetime import datetime, timezone
from pathlib import Path
import json

KNOWN_DEVICES_FILE = Path("known_devices.json")


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def load_devices():
    if not KNOWN_DEVICES_FILE.exists():
        return {}
    return json.loads(KNOWN_DEVICES_FILE.read_text())


def save_devices(data):
    KNOWN_DEVICES_FILE.write_text(json.dumps(data, indent=2))


def add_event(ip: str, message: str):
    devices = load_devices()
    device = devices.get(ip)

    if not device:
        return

    device.setdefault("events", [])
    device["events"].append({
        "timestamp": now_iso(),
        "message": message,
    })

    save_devices(devices)


def print_timeline(ip: str):
    devices = load_devices()
    device = devices.get(ip)

    if not device:
        print("❌ Device not found")
        return

    events = device.get("events", [])

    print(f"\n=== INCIDENT TIMELINE: {ip} ===\n")

    if not events:
        print("No events recorded for this device.\n")
        return

    for e in events:
        ts = e["timestamp"][:16].replace("T", " ")
        print(f"[{ts}] {e['message']}")

    print()
    