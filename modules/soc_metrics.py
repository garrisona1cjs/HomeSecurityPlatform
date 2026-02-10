from datetime import datetime
from pathlib import Path
import json

KNOWN_DEVICES_FILE = Path("known_devices.json")


def parse_iso(ts: str):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def load_devices():
    if not KNOWN_DEVICES_FILE.exists():
        return {}
    return json.loads(KNOWN_DEVICES_FILE.read_text())


def calculate_metrics():
    devices = load_devices()

    incidents_opened = 0
    incidents_closed = 0

    mttd_total = 0
    mttd_count = 0

    mttr_total = 0
    mttr_count = 0

    auto_actions = 0
    manual_actions = 0

    for d in devices.values():
        incident = d.get("incident")

        if incident:
            incidents_opened += 1

            opened_at = incident.get("opened_at")
            first_seen = d.get("first_seen")

            if opened_at and first_seen:
                mttd = (
                    parse_iso(opened_at) - parse_iso(first_seen)
                ).total_seconds()
                mttd_total += mttd
                mttd_count += 1

            if incident.get("status") == "CLOSED":
                incidents_closed += 1

                closed_at = incident.get("closed_at")
                if opened_at and closed_at:
                    mttr = (
                        parse_iso(closed_at) - parse_iso(opened_at)
                    ).total_seconds()
                    mttr_total += mttr
                    mttr_count += 1

        # Timeline action counts
        for e in d.get("events", []):
            msg = e.get("message", "").lower()
            if "blocked" in msg or "auto" in msg:
                auto_actions += 1
            if "manual" in msg:
                manual_actions += 1

    return {
        "incidents_opened": incidents_opened,
        "incidents_closed": incidents_closed,
        "mttd_seconds": int(mttd_total / mttd_count) if mttd_count else 0,
        "mttr_seconds": int(mttr_total / mttr_count) if mttr_count else 0,
        "auto_actions": auto_actions,
        "manual_actions": manual_actions,
    }


def print_metrics():
    m = calculate_metrics()

    print("\n=== SOC METRICS ===\n")
    print(f"Incidents Opened : {m['incidents_opened']}")
    print(f"Incidents Closed : {m['incidents_closed']}")
    print(f"MTTD            : {m['mttd_seconds']} seconds")
    print(f"MTTR            : {m['mttr_seconds']} seconds")
    print(f"Auto Actions    : {m['auto_actions']}")
    print(f"Manual Actions  : {m['manual_actions']}")
    print()
    