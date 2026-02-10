
OUI_VENDORS = {
    "00:1A:2B": "Cisco",
    "3C:5A:B4": "Google",
    "F4:F5:D8": "Apple",
    "DC:A6:32": "Raspberry Pi",
    "B8:27:EB": "Raspberry Pi",
    "44:65:0D": "Amazon",
    "E4:F0:42": "Samsung",
    "00:11:22": "TP-Link",
}


def get_vendor(mac_address: str) -> str:
    """
    Returns vendor name based on MAC OUI.
    """

    if not mac_address:
        return "Unknown"

    # Normalize MAC and extract OUI
    oui = mac_address.upper()[0:8]

    return OUI_VENDORS.get(oui, "Unknown")

