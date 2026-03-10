def projected_risk_score(device):
    """
    Predict future escalation risk.
    Safe: only increases awareness.
    """

    risk = device.get("risk_score", 0)

    # Escalation prediction logic
    if risk >= 75:
        risk += 10
    elif risk >= 50:
        risk += 5

    # Intelligence tags can increase projection
    if "high_risk_asn" in device.get("threat_tags", []):
        risk += 5

    return min(risk, 100)