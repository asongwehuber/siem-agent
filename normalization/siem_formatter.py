import json


def convert_to_siem_format(log):
    """
    Convert normalized logs into the format
    expected by the Mini-SIEM.
    """

    message = log.get("message")

    generator_id = log.get("generator_id", "")

    # =====================================================
    # ROUTER COLLECTOR
    # =====================================================

    if generator_id.startswith("router-"):

        if isinstance(message, dict):

            summary = message.get(
                "message",
                "Router network activity"
            )

        else:

            summary = str(message)

    # =====================================================
    # WINDOWS COLLECTOR
    # =====================================================

    elif isinstance(message, dict):

        event_id = message.get(
            "event_id",
            "Unknown"
        )

        event_type = (
            log.get(
                "event_type",
                "unknown"
            )
            .replace("_", " ")
            .title()
        )

        summary = (
            f"{event_type} "
            f"(Windows Event ID {event_id})"
        )

    # =====================================================
    # OTHER COLLECTORS
    # =====================================================

    else:

        summary = str(message)

    return {

        "generator_id": generator_id,

        "source_ip": (
            log.get("source_ip")
            or "127.0.0.1"
        ),

        "hostname": log.get(
            "hostname"
        ),

        "event_type": log.get(
            "event_type"
        ),

        "event_category": (
            log.get("event_category")
            or (
                message.get("event_category")
                if isinstance(message, dict)
                else None
            )
        ),

        "destination_port": log.get(
            "destination_port"
        ),

        "severity": log.get(
            "severity"
        ),

        # Always a string
        "message": summary

    }