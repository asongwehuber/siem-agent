from flask import Flask, request, jsonify
import re

from security.verifier import verify_signature
from normalization.formatter import normalize_log

from security.replay.protection import (
    validate_timestamp,
    check_duplicate_event
)

from sender import send_to_siem

app = Flask(__name__)


def convert_to_siem_format(log):

    message = log["message"]
    lower_message = message.lower()

    event_type = "unknown"
    severity = "low"

    source_ip = None
    destination_port = None

    # ==========================================
    # Extract Source IP
    # ==========================================
    ip_matches = re.findall(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        message
    )

    if ip_matches:
        source_ip = ip_matches[0]

    # ==========================================
    # Extract Destination Port
    # ==========================================
    arrow_match = re.search(
        r"->\s+\d+\.\d+\.\d+\.\d+:(\d{2,5})",
        message
    )

    if arrow_match:

        destination_port = int(
            arrow_match.group(1)
        )

    else:

        port_match = re.search(
            r"(?:port|:)\s*(\d{2,5})",
            message
        )

        if port_match:

            destination_port = int(
                port_match.group(1)
            )

    # ==========================================
    # Event Classification
    # ==========================================

    # Failed Login
    if (
        "failed password" in lower_message
        or "failed ssh" in lower_message
        or "failed login" in lower_message
        or "access denied" in lower_message
        or "authentication failure" in lower_message
        or '"401' in lower_message
        or "eventid=4625" in lower_message
    ):

        event_type = "failed_login"
        severity = "medium"

    # Successful Login
    elif (
        "accepted password" in lower_message
        or "successful login" in lower_message
        or "authenticated" in lower_message
        or "eventid=4624" in lower_message
    ):

        event_type = "successful_login"
        severity = "low"

    # Malware
    elif "malware" in lower_message:

        event_type = "malware_detected"
        severity = "critical"

    # Port Scan
    elif (
        "port scan" in lower_message
        or "scan detected" in lower_message
        or "nmap scripting engine" in lower_message
    ):

        event_type = "port_scan"
        severity = "high"

    # Privilege Escalation
    elif "privilege escalation" in lower_message:

        event_type = "privilege_escalation"
        severity = "critical"

    # Account Creation
    elif (
        "new user" in lower_message
        or "new database user" in lower_message
        or "newaccount" in lower_message
        or "eventid=4720" in lower_message
    ):

        event_type = "account_creation"
        severity = "high"

    # Account Deletion
    elif (
        "deletedaccount" in lower_message
        or "eventid=4726" in lower_message
    ):

        event_type = "account_deletion"
        severity = "medium"

    # Audit Log Tampering
    elif (
        "auditlogcleared" in lower_message
        or "audit log cleared" in lower_message
        or "eventid=1102" in lower_message
    ):

        event_type = "log_tampering"
        severity = "critical"

    # SQL Injection
    elif (
        "sql injection" in lower_message
        or "sqlmap" in lower_message
        or "suspicious query" in lower_message
    ):

        event_type = "sql_injection_attempt"
        severity = "high"

    # Suspicious Outbound Traffic
    elif "suspicious outbound traffic" in lower_message:

        event_type = "suspicious_outbound"
        severity = "medium"

    # Database Shutdown
    elif "shutdown" in lower_message:

        event_type = "service_failure"
        severity = "medium"

    # Data Exfiltration
    elif "large data export" in lower_message:

        event_type = "data_exfiltration"
        severity = "high"

    # Configuration Change
    elif "configuration changed" in lower_message:

        event_type = "configuration_change"
        severity = "medium"

    return {

        "source_ip": source_ip,

        "hostname": log["hostname"],

        "event_type": event_type,

        "event_category": event_type,

        "destination_port": destination_port,

        "severity": severity,

        "message": message

    }


@app.route("/receive-log", methods=["POST"])
def receive_log():

    log = request.get_json()

    if not log:

        return jsonify(
            {
                "error": "No JSON received"
            }
        ), 400

    if not verify_signature(log):

        return jsonify(
            {
                "status": "rejected",
                "reason": "Invalid signature"
            }
        ), 401

    if not validate_timestamp(
        log["timestamp"]
    ):

        return jsonify(
            {
                "status": "rejected",
                "reason": "Expired timestamp"
            }
        ), 401

    if not check_duplicate_event(log):

        return jsonify(
            {
                "status": "rejected",
                "reason": "Duplicate event"
            }
        ), 401

    # Normalize the incoming log
    normalized_log = normalize_log(log)

    # Convert to Mini SIEM format
    siem_log = convert_to_siem_format(
        normalized_log
    )

    # Forward to Mini SIEM
    siem_response = send_to_siem(
        siem_log
    )

    return jsonify(
        {
            "status": "accepted",
            "message": "Log verified, normalized and forwarded",
            "normalized_log": normalized_log,
            "siem_log": siem_log,
            "siem_response": siem_response
        }
    ), 200


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=6000,
        debug=True
    )