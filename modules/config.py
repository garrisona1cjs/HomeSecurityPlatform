from pathlib import Path
import yaml

CONFIG_FILE = Path("config.yaml")

DEFAULT_CONFIG = {
    "risk": {
        "incident_threshold": 70,
        "block_threshold": 85,
        "daily_decay": 5,
        "minimum_risk": 0,
    },
    "alerts": {
        "new_device_grace_period": 300,
        "auto_trust_days": 7,
    },
    "enforcement": {
        "firewall_enabled": True,
        "manual_unblock_required": True,
    },
    "logging": {
        "color_enabled": True,
        "daily_summary": True,
    },
}


def load_config():
    if not CONFIG_FILE.exists():
        return DEFAULT_CONFIG
    return yaml.safe_load(CONFIG_FILE.read_text())
