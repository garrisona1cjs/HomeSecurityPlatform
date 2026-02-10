# =========================
# Device Risk Scoring
# =========================

def calculate_risk(device: dict, correlated: bool = False) -> int:
    """
    Calculate a 0–100 risk score for a device.
    """

    score = 0

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

    # Clamp score
    score = max(0, min(score, 100))
    return score
