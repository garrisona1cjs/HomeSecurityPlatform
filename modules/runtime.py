from modules.config import load_config

CONFIG = load_config()

SAFE_MODE = False


def enable_safe_mode():
    global SAFE_MODE
    SAFE_MODE = True


def is_safe_mode() -> bool:
    return SAFE_MODE or CONFIG.get("enforcement", {}).get("safe_mode", False)
