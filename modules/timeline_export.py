import json
import csv
from pathlib import Path

KNOWN_DEVICES_FILE = Path("known_devices.json")
EXPORT_DIR = Path("exports")


def load_devices():
    if not KNOWN_DEVICES_FILE.exists():
        return {}
    return json.loads(KNOWN_DEVICES_FILE.read_text())


def ensure_export_dir():
    EXPORT_DIR.mkdir(exist_ok=True)


def export_timeline_json(ip: str):
    devices = load_devices()
    device = devices.get(ip)

    if not device:
        print("❌ Device not found")
        return

    events = device.get("events", [])

    ensure_export_dir()

    payload = {
        "ip": ip,
        "event_count": len(events),
        "events": events,
    }

    out = EXPORT_DIR / f"timeline_{ip}.json"
    out.write_text(json.dumps(payload, indent=2))

    print(f"✅ Timeline exported to {out}")


def export_timeline_csv(ip: str):
    devices = load_devices()
    device = devices.get(ip)

    if not device:
        print("❌ Device not found")
        return

    events = device.get("events", [])

    ensure_export_dir()

    out = EXPORT_DIR / f"timeline_{ip}.csv"

    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "event"])

        for e in events:
            writer.writerow([e.get("timestamp"), e.get("message")])

    print(f"✅ Timeline exported to {out}")
    