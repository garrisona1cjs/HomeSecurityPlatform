import json
import os
from pathlib import Path
from typing import Any

KNOWN_DEVICES_FILE = Path("known_devices.json")
BACKUP_FILE = Path("known_devices.json.bak")
TEMP_FILE = Path("known_devices.json.tmp")


def atomic_write_json(path: Path, data: Any):
    """
    Write JSON atomically with backup.
    """
    # Write temp file
    with TEMP_FILE.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())

    # Backup existing file
    if path.exists():
        path.replace(BACKUP_FILE)

    # Replace with temp
    TEMP_FILE.replace(path)


def safe_load_json(path: Path) -> dict:
    """
    Load JSON safely. Recover from backup if corrupted.
    """
    if not path.exists():
        return {}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print("⚠️  WARNING: known_devices.json is corrupted")

        if BACKUP_FILE.exists():
            print("⚠️  Restoring from backup")
            path.unlink(missing_ok=True)
            BACKUP_FILE.replace(path)
            return json.loads(path.read_text(encoding="utf-8"))

        print("⚠️  No valid backup found — starting with empty state")
        return {}