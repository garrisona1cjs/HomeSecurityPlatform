import subprocess
import platform

from modules.severity import alert

# =========================
# Configuration
# =========================

RULE_PREFIX = "HSP_BLOCK_"
DRY_RUN = False   # 🚨 REAL BLOCKING ENABLED

# =========================
# Platform Detection
# =========================

def is_windows():
    return platform.system().lower() == "windows"

def is_linux():
    return platform.system().lower() == "linux"

# =========================
# Firewall Control
# =========================

def block_device(ip: str):
    rule_name = f"{RULE_PREFIX}{ip}"

    if DRY_RUN:
        alert("HIGH", f"[DRY-RUN] Would block {ip}")
        return

    try:
        if is_windows():
            subprocess.run(
                [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f"name={rule_name}",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip}"
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            alert("HIGH", f"Firewall block applied to {ip}")

        elif is_linux():
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True
            )

            alert("HIGH", f"iptables block applied to {ip}")

        else:
            alert("MEDIUM", f"Unsupported OS for firewall block: {ip}")

    except Exception as e:
        alert("HIGH", f"Firewall block FAILED for {ip}: {e}")


def unblock_device(ip: str):
    rule_name = f"{RULE_PREFIX}{ip}"

    if DRY_RUN:
        alert("LOW", f"[DRY-RUN] Would unblock {ip}")
        return

    try:
        if is_windows():
            subprocess.run(
                [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    f"name={rule_name}"
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            alert("LOW", f"Firewall block removed for {ip}")

        elif is_linux():
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True
            )

            alert("LOW", f"iptables unblock applied to {ip}")

    except Exception as e:
        alert("HIGH", f"Firewall unblock FAILED for {ip}: {e}")
        






