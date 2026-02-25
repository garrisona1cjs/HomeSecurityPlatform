from modules.threat_intel import evaluate_asn_threat

# =========================
# Device Risk Scoring
# =========================

def calculate_risk(device: dict, correlated: bool = False):
    """
    Calculate a 0–100 risk score for a device.
    """

    score = 0
    threat_tags = []

    # Base risk factors
    if not device.get("trusted", False):
        score += 20

    if device.get("vendor") == "Unknown":
        score += 15

    if device.get("manual_override"):
        score -= 10

    # Event-based indicators
    if device.get("alerted_new"):
        score += 25

    if correlated:
        score += 30

    # =========================
    # ASN Threat Intelligence
    # =========================
    asn = device.get("asn")
    country_code = device.get("country_code")

    asn_boost, intel_tags = evaluate_asn_threat(asn, country_code)
    score += asn_boost
    threat_tags.extend(intel_tags)

    # Clamp score
    score = max(0, min(score, 100))

    return score, threat_tags
