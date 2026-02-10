import sys
import json
from pathlib import Path
from datetime import datetime, timezone

from modules.enforcement import enforce_manual_allow
from modules.timeline import add_event

KNOWN_DEVICES_FILE = Path("known_devices.json")


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def load_devices():
    if not KNOWN_DEVICES_FILE.exists():
        return {}
    return json.loads(KNOWN_DEVICES_FILE.read_text())


def save_devices(data):
    KNOWN_DEVICES_FILE.write_text(json.dumps(data, indent=2))


def list_devices():
    devices = load_devices()

    print("\nIP ADDRESS        TRUSTED  RISK  FIRST SEEN")
    print("-" * 60)

    for ip, d in devices.items():
        print(
            f"{ip:<17} "
            f"{str(d.get('trusted', False)):<8} "
            f"{d.get('risk_score', 0):<5} "
            f"{d.get('first_seen', '')}"
        )


def allow_device(ip):
    devices = load_devices()
    device = devices.get(ip)

    if not device:
        print("❌ Device not found")
        return

    device["trusted"] = True
    device["manual_override"] = True
    device["trusted_since"] = now_iso()
    device["risk_score"] = max(0, device.get("risk_score", 0) - 30)

    enforce_manual_allow(device)
    add_event(ip, "Manually allowed by analyst")

    save_devices(devices)
    print(f"✅ Device manually allowed and unblocked: {ip}")


def deny_device(ip):
    devices = load_devices()
    device = devices.get(ip)

    if not device:
        print("❌ Device not found")
        return

    device["trusted"] = False
    device["manual_override"] = False
    device["risk_score"] = max(device.get("risk_score", 0), 70)

    add_event(ip, "Manually denied by analyst")

    save_devices(devices)
    print(f"🚫 Device manually denied: {ip}")


def main():
    if len(sys.argv) < 2:
        print("Usage: manage_devices.py list | allow <ip> | deny <ip>")
        return

    cmd = sys.argv[1]

    if cmd == "list":
        list_devices()
    elif cmd == "allow" and len(sys.argv) == 3:
        allow_device(sys.argv[2])
    elif cmd == "deny" and len(sys.argv) == 3:
        deny_device(sys.argv[2])
    else:
        print("Invalid command")


if __name__ == "__main__":
    main()
    

    
