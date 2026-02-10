from scapy.all import ARP, Ether, srp
from modules.logger import log_event
from modules.vendor_lookup import get_vendor

def discover_lan_devices(network="192.168.1.0/24"):
    log_event(f"Starting LAN discovery on {network}")

    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _ = srp(packet, timeout=2, verbose=False)

    devices = []

    for _, received in answered:
        device = {
            "ip": received.psrc,
            "mac": received.hwsrc,
            "vendor": get_vendor(received.hwsrc)
        }
        devices.append(device)
        log_event(f"Device found: {device}")

    return devices












