import socket
import subprocess


def get_local_ip() -> str:
    hostname = socket.gethostname()
    return socket.gethostbyname(hostname)


def get_default_gateway() -> str | None:
    try:
        output = subprocess.check_output(
            ["route", "print", "0.0.0.0"],
            text=True,
        )
        for line in output.splitlines():
            if "0.0.0.0" in line:
                parts = line.split()
                if len(parts) >= 3:
                    return parts[2]
    except Exception:
        pass
    return None


def is_protected_ip(ip: str) -> bool:
    if ip in ("127.0.0.1", "localhost"):
        return True

    local_ip = get_local_ip()
    if ip == local_ip:
        return True

    gateway = get_default_gateway()
    if gateway and ip == gateway:
        return True

    return False
