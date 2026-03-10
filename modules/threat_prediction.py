import math
from datetime import datetime

def predict_trajectory(threat):
    """
    Predict next position based on velocity and direction.
    """
    if "velocity" not in threat or "direction" not in threat:
        return threat

    dx = math.cos(math.radians(threat["direction"])) * threat["velocity"]
    dy = math.sin(math.radians(threat["direction"])) * threat["velocity"]

    threat["predicted_lat"] = threat["lat"] + dy
    threat["predicted_lon"] = threat["lon"] + dx
    threat["prediction_time"] = datetime.utcnow().isoformat()

    return threat


def projected_impact_score(threat):
    """
    Calculate projected damage risk.
    """
    base = threat.get("risk_score", 0)

    if threat.get("classification") == "botnet":
        base += 10
    if threat.get("classification") == "apt":
        base += 20
    if threat.get("classification") == "ddos":
        base += 15

    return min(base, 100)