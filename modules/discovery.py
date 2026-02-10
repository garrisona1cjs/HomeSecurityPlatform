import subprocess
import ipaddress
import re
import socket
from pathlib import Path

LAST_LAN_FILE = Path(".last_lan_ip")


# =========================
# Windows Interface Discovery
# =========================
def get_windows_ipv4_addresses() -> list[str]:
    try:
        result = subprocess.run(
            ["ipconfig"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:
        return []

    ips = []

    for line in result.stdout.splitlines():
        if "IPv4 Address" in line:
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if match:
                ip = match.group(1)
                addr = ipaddress.ip_address(ip)
                if addr.is_private and not addr.is_loopback:
                    ips.append(ip)

    return ips


def is_virtual_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return addr in ipaddress.ip_network("172.16.0.0/12")


def load_last_lan_ip() -> str | None:
    if LAST_LAN_FILE.exists():
        return LAST_LAN_FILE.read_text().strip()
    return None


def save_last_lan_ip(ip: str):
    LAST_LAN_FILE.write_text(ip)


def select_real_lan_ip() -> str | None:
    ips = get_windows_ipv4_addresses()

    # 1️⃣ Prefer last known good LAN
    last_ip = load_last_lan_ip()
    if last_ip and last_ip in ips:
        return last_ip

    candidates = [ip for ip in ips if not is_virtual_ip(ip)]

    # 2️⃣ Prefer common home LAN ranges
    for ip in candidates:
        if ip.startswith("192.168."):
            save_last_lan_ip(ip)
            return ip

    for ip in candidates:
        if ip.startswith("10."):
            save_last_lan_ip(ip)
            return ip

    if candidates:
        save_last_lan_ip(candidates[0])
        return candidates[0]

    return None


def network_from_ip(ip: str) -> str:
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


# =========================
# Nmap Discovery
# =========================
def nmap_scan(network: str) -> list[dict]:
    devices = []

    try:
        result = subprocess.run(
            ["nmap", "-sn", network],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except Exception:
        return devices

    current_ip = None

    for line in result.stdout.splitlines():
        line = line.strip()

        if line.startswith("Nmap scan report for"):
            current_ip = line.split()[-1]

        elif "MAC Address:" in line and current_ip:
            parts = line.split("MAC Address:")[1].strip()
            mac = parts.split()[0]
            vendor = " ".join(parts.split()[1:]).strip("()")

            devices.append({
                "ip": current_ip,
                "mac": mac,
                "vendor": vendor or "Unknown",
            })
            current_ip = None

    return devices


# =========================
# Unified Discovery
# =========================
def discover_devices() -> list[dict]:
    lan_ip = select_real_lan_ip()

    if lan_ip:
        network = network_from_ip(lan_ip)
        devices = nmap_scan(network)
        if devices:
            return devices

    return [
        {
            "ip": socket.gethostbyname(socket.gethostname()),
            "mac": "UNKNOWN",
            "vendor": "Local Host",
        }
    ]



