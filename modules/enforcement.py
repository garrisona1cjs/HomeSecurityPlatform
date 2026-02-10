import subprocess

from modules.logger import log_event
from modules.severity import alert
from modules.privileges import require_admin_or_warn
from modules.config import load_config
from modules.network_guardrails import is_protected_ip
from modules.runtime import is_safe_mode

CONFIG = load_config()
ADMIN_OK = require_admin_or_warn()

RISK_BLOCK_THRESHOLD = CONFIG["risk"]["block_threshold"]
RULE_PREFIX = "HSP_BLOCK_"


def firewall_rule_exists(ip: str) -> bool:
    if is_safe_mode():
        return False

    if not ADMIN_OK or not CONFIG["enforcement"]["firewall_enabled"]:
        return False

    rule_name = f"{RULE_PREFIX}{ip}"
    cmd = [
        "netsh",
        "advfirewall",
        "firewall",
        "show",
        "rule",
        f"name={rule_name}",
    ]

    result = subprocess.run(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    return result.returncode == 0


def create_firewall_rule(ip: str):
    if is_safe_mode():
        return

    if not ADMIN_OK or not CONFIG["enforcement"]["firewall_enabled"]:
        return

    rule_name = f"{RULE_PREFIX}{ip}"

    commands = [
        [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip}",
        ],
        [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=out",
            "action=block",
            f"remoteip={ip}",
        ],
    ]

    for cmd in commands:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def remove_firewall_rule(ip: str):
    if is_safe_mode():
        return

    if not ADMIN_OK:
        return

    rule_name = f"{RULE_PREFIX}{ip}"
    subprocess.run(
        [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name={rule_name}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def evaluate_enforcement(device: dict):
    if is_safe_mode():
        return

    if not ADMIN_OK:
        return

    ip = device.get("ip")
    risk = device.get("risk_score", 0)

    if is_protected_ip(ip):
        return

    if device.get("trusted") or device.get("manual_override"):
        return

    if risk < RISK_BLOCK_THRESHOLD:
        return

    if firewall_rule_exists(ip):
        return

    create_firewall_rule(ip)

    alert("HIGH", f"Device BLOCKED via firewall: {ip} (risk={risk})")

    log_event(
        "HIGH",
        "BLOCKED device via Windows Firewall",
        ip=ip,
        risk_score=risk,
    )


def enforce_manual_allow(device: dict):
    if is_safe_mode():
        return

    if not ADMIN_OK:
        return

    ip = device.get("ip")

    if is_protected_ip(ip):
        return

    if firewall_rule_exists(ip):
        remove_firewall_rule(ip)

        alert("LOW", f"Firewall block removed for trusted device: {ip}")

        log_event(
            "INFO",
            "UNBLOCKED device via manual allow",
            ip=ip,
        )
        
        
        

        