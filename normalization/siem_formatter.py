def convert_to_siem_format(log):

    return {

        "generator_id": log.get("generator_id"),

        "source_ip": log.get("source_ip"),

        "hostname": log.get("hostname"),

        "event_type": log.get("event_type"),

        "event_category": log.get("event_category"),

        "destination_port": log.get("destination_port"),

        "severity": log.get("severity"),

        "message": log.get("message")

    }