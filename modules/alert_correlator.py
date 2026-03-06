# modules/alert_correlator.py

from modules.incident_engine import (
    find_existing_incident,
    create_incident,
    update_incident,
)


def correlate_alert(db, alert_data):
    """
    Determine whether an alert belongs to an existing incident.
    """

    incident = find_existing_incident(
        db,
        alert_data["source_ip"],
        alert_data["asn"]
    )

    if incident:
        return update_incident(db, incident)

    return create_incident(db, alert_data)