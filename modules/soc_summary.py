import json
from pathlib import Path
from datetime import datetime, timezone

from modules.logger import log_event

KNOWN_DEVICES_FILE = Path("known_devices.json")
LAST_SUMMARY_FILE = Path(".last_soc_summary")
CORRELATION_STATE_FILE = Path(".correlation_state.json")


def load_known_devices():
    if not KNOWN_DEVICES_FILE.exists():
        return {}
    return json.loads(KNOWN_DEVICES_FILE.read_text())


def load_correlation_state():
    if not CORRELATION_STATE_FILE.exists():
        return {}
    return json.loads(CORRELATION_STATE_FILE.read_text())


def summarize_devices(devices: dict):
    risks = [d.get("risk_score", 0) for d in devices.values()]
    avg_risk = round(sum(risks) / len(risks), 1) if risks else 0
    max_risk = max(risks) if risks else 0

    return avg_risk, max_risk


def print_summary():
    devices = load_known_devices()
    correlation = load_correlation_state()
    avg_risk, max_risk = summarize_devices(devices)

    now = datetime.now(timezone.utc).isoformat()

    print("\n=== SOC SECURITY SUMMARY ===")
    print(f"Timestamp (UTC): {now}")
    print("-" * 40)
    print(f"Total devices        : {len(devices)}")
    print(f"Average risk score   : {avg_risk}")
    print(f"Highest device risk  : {max_risk}")
    print(f"Correlated devices   : {len(correlation)}")
    print("-" * 40)

    if max_risk >= 70:
        print("🚨 SOC ACTION: High-risk device investigation required")
    elif max_risk >= 40:
        print("⚠️  SOC ACTION: Elevated risk devices present")
    else:
        print("✅ SOC STATUS: Network stable")

    print()


def log_daily_summary():
    today = datetime.now(timezone.utc).date().isoformat()

    if LAST_SUMMARY_FILE.exists():
        if LAST_SUMMARY_FILE.read_text().strip() == today:
            return

    devices = load_known_devices()
    avg_risk, max_risk = summarize_devices(devices)

    log_event(
        "INFO",
        "Daily SOC risk summary",
        date=today,
        total_devices=len(devices),
        average_risk=avg_risk,
        highest_risk=max_risk,
    )

    LAST_SUMMARY_FILE.write_text(today)


    
