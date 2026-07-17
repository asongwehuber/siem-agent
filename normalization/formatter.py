import re


def normalize_log(log):

    message = log["message"]

    generator = log["generator_id"]


    normalized = {

        "source_ip": extract_ip(message),

        "hostname": log["hostname"],

        "event_type": detect_event_type(message),

        "severity": detect_severity(message),

        "destination_port": extract_port(message),

        "message": message

    }


    return normalized



def extract_ip(message):

    ips = re.findall(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        message
    )

    if ips:
        return ips[0]

    return "unknown"



def extract_port(message):

    ports = re.findall(
        r':(\d{2,5})',
        message
    )

    if ports:
        return int(ports[-1])

    return None



def detect_event_type(message):

    msg = message.lower()


    if "failed password" in msg:
        return "failed_login"


    if "accepted password" in msg:
        return "successful_login"


    if "port scan" in msg:
        return "port_scan"


    if "malware" in msg:
        return "malware_detected"


    if "privilege escalation" in msg:
        return "privilege_escalation"


    if "auditlogcleared" in msg:
        return "log_cleared"


    return "unknown"



def detect_severity(message):

    msg = message.lower()


    if (
        "malware" in msg
        or
        "privilege escalation" in msg
        or
        "auditlogcleared" in msg
    ):
        return "critical"


    if (
        "failed password" in msg
        or
        "port scan" in msg
    ):
        return "medium"


    return "low"