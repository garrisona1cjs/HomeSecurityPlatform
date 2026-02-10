import ctypes
import sys


def is_admin() -> bool:
    """
    Check if the current process has administrator privileges.
    Windows-only.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def require_admin_or_warn() -> bool:
    """
    Returns True if admin, False if not.
    Does NOT exit — SOC tools should fail safely.
    """
    if not is_admin():
        print("⚠️  WARNING: Running without administrator privileges")
        print("⚠️  Firewall enforcement will be DISABLED")
        print("⚠️  Detection and SOC functions will continue\n")
        return False
    return True
