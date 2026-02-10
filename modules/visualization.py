from datetime import datetime
from pathlib import Path
import json

KNOWN_DEVICES_FILE = Path("known_devices.json")
MAX_BAR_WIDTH = 20


def parse_iso(ts: str):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def load_devices():
    if not KNOWN_DEVICES_FILE.exists():
        return {}
    return json.loads(KNOWN_DEVICES_FILE.read_text())


def draw_bar(value: int) -> str:
    filled = int((value / 100) * MAX_BAR_WIDTH)
    return "█" * filled + " " * (MAX_BAR_WIDTH - filled)


def print_risk_history():
    devices = load_devices()

    print("\n=== RISK HISTORY ===\n")

    for ip, d in devices.items():
        history = d.get("risk_history", [])
        if not history:
            continue

        print(ip)
        for entry in history:
            bar = draw_bar(entry["risk_score"])
            print(f"{entry['date']} | {bar} {entry['risk_score']}")
        print()


def print_incident_summary():
    devices = load_devices()

    print("\n=== INCIDENT SUMMARY ===\n")

    for d in devices.values():
        incident = d.get("incident")
        if not incident:
            continue

        opened = incident.get("opened_at")
        closed = incident.get("closed_at")

        duration = "OPEN"
        if opened and closed:
            delta = parse_iso(closed) - parse_iso(opened)
            seconds = int(delta.total_seconds())
            minutes = seconds // 60
            seconds = seconds % 60
            duration = f"{minutes}m {seconds}s"

        print(
            f"{incident['id']} | "
            f"{d['ip']} | "
            f"{incident['severity']} | "
            f"{incident['status']} | "
            f"{duration}"
        )
        