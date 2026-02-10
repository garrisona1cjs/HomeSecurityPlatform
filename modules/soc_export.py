import json
import csv
from pathlib import Path
from datetime import datetime, timezone

KNOWN_DEVICES_FILE = Path("known_devices.json")
EXPORT_DIR = Path("exports")


def load_known_devices() -> dict:
    if not KNOWN_DEVICES_FILE.exists():
        return {}
    return json.loads(KNOWN_DEVICES_FILE.read_text())


def ensure_export_dir():
    EXPORT_DIR.mkdir(exist_ok=True)


def export_json():
    ensure_export_dir()
    devices = load_known_devices()

    payload = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "device_count": len(devices),
        "devices": list(devices.values()),
    }

    out = EXPORT_DIR / "soc_devices.json"
    out.write_text(json.dumps(payload, indent=2))
    print(f"✅ SOC data exported to {out}")


def export_csv():
    ensure_export_dir()
    devices = load_known_devices()

    out = EXPORT_DIR / "soc_devices.csv"

    fieldnames = [
        "ip",
        "mac",
        "vendor",
        "trusted",
        "manual_override",
        "risk_score",
        "first_seen",
    ]

    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for d in devices.values():
            writer.writerow({
                "ip": d.get("ip"),
                "mac": d.get("mac"),
                "vendor": d.get("vendor"),
                "trusted": d.get("trusted"),
                "manual_override": d.get("manual_override"),
                "risk_score": d.get("risk_score"),
                "first_seen": d.get("first_seen"),
            })

    print(f"✅ SOC data exported to {out}")
    