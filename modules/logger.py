from datetime import datetime, timezone
from pathlib import Path
import json

from modules.colors import disable_color, enable_color

LOG_FILE = Path("security.log")


def log_event(level: str, message: str, **fields):
    """
    Write a structured, color-free log entry.
    """
    disable_color()  # 🔒 force plain text for logs

    timestamp = datetime.now(timezone.utc).isoformat()

    entry = {
        "timestamp": timestamp,
        "level": level,
        "message": message,
        **fields,
    }

    LOG_FILE.open("a", encoding="utf-8").write(
        json.dumps(entry) + "\n"
    )

    enable_color()  # 🔓 restore color for console
    





