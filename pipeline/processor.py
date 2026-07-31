from flask import jsonify

from security.verifier import verify_signature

from security.replay.protection import (
    validate_timestamp,
    check_duplicate_event
)

from normalization.formatter import normalize_log
from normalization.siem_formatter import (
    convert_to_siem_format
)

from sender import send_to_siem


def process_message(log):

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

    normalized_log = normalize_log(log)
    print("\n========== NORMALIZED LOG ==========")
    print(normalized_log)
    print("====================================\n")

    siem_log = convert_to_siem_format(
        normalized_log
    )
    print("\n========== SIEM LOG ==========")
    print(siem_log)
    print("================================\n")

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