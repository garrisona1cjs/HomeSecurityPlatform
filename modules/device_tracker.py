from datetime import datetime, timezone
from pathlib import Path

from modules.severity import alert
from modules.logger import log_event
from modules.alert_correlation import add_signal
from modules.risk_scoring import calculate_risk
from modules.risk_decay import apply_risk_decay
from modules.enforcement import evaluate_enforcement
from modules.timeline import add_event
from modules.incidents import open_incident, close_incident
from modules.risk_history import record_risk_snapshot
from modules.config import load_config
from modules.storage import safe_load_json, atomic_write_json
from modules.runtime import is_safe_mode

KNOWN_DEVICES_FILE = Path("known_devices.json")
CONFIG = load_config()


def now_utc():
    return datetime.now(timezone.utc)


def now_iso():
    return now_utc().isoformat()


def parse_iso(ts: str):
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def seconds_since(ts: str) -> int:
    return int((now_utc() - parse_iso(ts)).total_seconds())


def normalize_mac(mac: str) -> str:
    return mac.lower()


def load_known_devices() -> dict:
    data = safe_load_json(KNOWN_DEVICES_FILE)

    for d in data.values():
        d.setdefault("risk_score", 0)
        d.setdefault("events", [])
        d.setdefault("risk_history", [])
        if "mac" in d:
            d["mac"] = normalize_mac(d["mac"])

    return data


def save_known_devices(data: dict):
    if is_safe_mode():
        return
    atomic_write_json(KNOWN_DEVICES_FILE, data)


def detect_new_devices(current_devices: list[dict]) -> list[dict]:
    if not is_safe_mode():
        apply_risk_decay()

    known_devices = load_known_devices()
    new_devices = []
    changed = False

    for device in current_devices:
        ip = device["ip"]
        mac = normalize_mac(device["mac"])
        vendor = device.get("vendor", "Unknown")

        stored = known_devices.get(ip)
        correlated = False

        if not stored:
            if is_safe_mode():
                continue

            known_devices[ip] = {
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "first_seen": now_iso(),
                "trusted": False,
                "manual_override": False,
                "vendor_warned": False,
                "alerted_new": False,
                "risk_score": 25,
                "events": [],
                "risk_history": [],
            }
            add_event(ip, "First seen on network")
            changed = True
            continue

        if not stored.get("alerted_new"):
            if seconds_since(stored["first_seen"]) >= CONFIG["alerts"]["new_device_grace_period"]:
                correlated = add_signal(ip, "HIGH", "new_device")
                alert("HIGH", f"New device detected: {ip}")

                if not is_safe_mode():
                    add_event(ip, "New device alert triggered")
                    stored["alerted_new"] = True
                    new_devices.append(device)
                    changed = True

        if vendor == "Unknown" and not stored.get("vendor_warned"):
            correlated = add_signal(ip, "MEDIUM", "unknown_vendor")
            alert("MEDIUM", f"Unknown vendor: {ip}")

            if not is_safe_mode():
                add_event(ip, "Unknown vendor detected")
                stored["vendor_warned"] = True
                changed = True

        risk_score, threat_tags = calculate_risk(stored, correlated)

        stored["risk_score"] = risk_score
        stored["threat_tags"] = threat_tags

        # Escalate incident for malicious infrastructure
        if "malicious_asn" in threat_tags and not stored.get("malicious_flagged"):
             open_incident(ip, "CRITICAL", "Malicious ASN detected")
             add_event(ip, "Incident opened (malicious ASN)")
             stored["malicious_flagged"] = True

        if not is_safe_mode():
            record_risk_snapshot(ip, stored["risk_score"])

            if stored["risk_score"] >= CONFIG["risk"]["incident_threshold"]:
                open_incident(ip, "HIGH", "Risk score exceeded threshold")
                add_event(ip, "Incident opened (risk threshold exceeded)")
            else:
                close_incident(ip, "Risk score normalized")

            evaluate_enforcement(stored)

    if changed:
        save_known_devices(known_devices)
        log_event("INFO", "Known devices updated")

    return new_devices















































