import json


def convert_to_siem_format(log):
    """
    Convert normalized logs into the format
    expected by the Mini-SIEM.
    """

    message = log.get("message")

    # Windows collector sends a dictionary
    if isinstance(message, dict):

        event_id = message.get("event_id", "Unknown")

        event_type = (
            log.get("event_type", "unknown")
            .replace("_", " ")
            .title()
        )

        summary = (
            f"{event_type} "
            f"(Windows Event ID {event_id})"
        )

    # Log Generator sends a plain string
    else:

        summary = str(message)

    return {

        "generator_id": log.get("generator_id"),

        "source_ip": log.get("source_ip") or "127.0.0.1",

        "hostname": log.get("hostname"),

        "event_type": log.get("event_type"),

        "event_category": log.get("event_category"),

        "destination_port": log.get("destination_port"),

        "severity": log.get("severity"),

        # Always a string
        "message": summary

    }