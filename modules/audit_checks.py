from pathlib import Path
import json

from modules.severity import alert
from modules.logger import log_event

KNOWN_DEVICES_FILE = Path("known_devices.json")


def load_devices():
    if not KNOWN_DEVICES_FILE.exists():
        return {}
    return json.loads(KNOWN_DEVICES_FILE.read_text())


def run_audit_checks():
    devices = load_devices()

    for ip, d in devices.items():
        events = d.get("events", [])
        incident = d.get("incident")
        risk = d.get("risk_score", 0)
        blocked = d.get("blocked", False)

        # -------------------------
        # Incident with no timeline
        # -------------------------
        if incident and not events:
            alert("WARN", f"Audit: Incident without timeline for {ip}")
            log_event(
                "WARN",
                "Audit issue: Incident without timeline",
                ip=ip,
            )

        # -------------------------
        # Blocked without incident
        # -------------------------
        if blocked and not incident:
            alert("WARN", f"Audit: Blocked device without incident {ip}")
            log_event(
                "WARN",
                "Audit issue: Blocked without incident",
                ip=ip,
            )

        # -------------------------
        # High risk without incident
        # -------------------------
        if risk >= 70 and not incident:
            alert("WARN", f"Audit: High risk without incident {ip}")
            log_event(
                "WARN",
                "Audit issue: High risk without incident",
                ip=ip,
                risk_score=risk,
            )

        # -------------------------
        # Closed incident without closure reason
        # -------------------------
        if incident and incident.get("status") == "CLOSED":
            if not incident.get("closure_reason"):
                alert("WARN", f"Audit: Incident closed without reason {ip}")
                log_event(
                    "WARN",
                    "Audit issue: Closed incident missing reason",
                    ip=ip,
                )

        # -------------------------
        # Missing risk history
        # -------------------------
        if not d.get("risk_history"):
            alert("WARN", f"Audit: Missing risk history for {ip}")
            log_event(
                "WARN",
                "Audit issue: Missing risk history",
                ip=ip,
            )
            