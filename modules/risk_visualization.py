from datetime import datetime, timezone
from pathlib import Path
import json

from modules.colors import colorize

KNOWN_DEVICES_FILE = Path("known_devices.json")
DECAY_PER_DAY = 5
BAR_WIDTH = 20


def now_utc():
    return datetime.now(timezone.utc)


def load_devices() -> dict:
    if not KNOWN_DEVICES_FILE.exists():
        return {}
    return json.loads(KNOWN_DEVICES_FILE.read_text())


def days_since(ts: str) -> int:
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (now_utc() - dt).days


def risk_level(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 15:
        return "LOW"
    return "INFO"


def risk_bar(score: int) -> str:
    filled = int((score / 100) * BAR_WIDTH)
    empty = BAR_WIDTH - filled
    return "█" * filled + "░" * empty


def print_risk_decay():
    devices = load_devices()

    if not devices:
        print("No device data available.")
        return

    print("\n=== DEVICE RISK DECAY VIEW ===")
    print("IP ADDRESS        RISK TREND")
    print("-" * 65)

    for ip, d in sorted(
        devices.items(),
        key=lambda x: x[1].get("risk_score", 0),
        reverse=True,
    ):
        current = d.get("risk_score", 0)
        last_update = d.get("last_risk_update")
        days = days_since(last_update) if last_update else 0
        projected = max(0, current - (days * DECAY_PER_DAY))

        level = risk_level(current)
        bar = risk_bar(current)

        line = f"{ip:<17} [{bar}] {current} → {projected} ({days}d)"
        print(colorize(line, level))

    print("\nLegend:")
    print(colorize("  HIGH   ≥ 70", "HIGH"))
    print(colorize("  MEDIUM ≥ 40", "MEDIUM"))
    print(colorize("  LOW    ≥ 15", "LOW"))
    print(colorize("  INFO   < 15", "INFO"))
    print()
    
