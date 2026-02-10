import socket

from modules.logger import log_event


def discover_local_host():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)

    log_event(f"Local host detected: {hostname} ({ip_address})")
    return hostname, ip_address

