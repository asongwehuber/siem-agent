from flask import Flask, request, jsonify

from database.heartbeat_db import update_heartbeat

from security.verifier import verify_signature

from normalization.formatter import normalize_log
from normalization.siem_formatter import (
    convert_to_siem_format
)

from security.replay.protection import (
    validate_timestamp,
    check_duplicate_event
)

from sender import send_to_siem
from pipeline.processor import process_message

app = Flask(__name__)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "siem-agent"
    }), 200


@app.route("/receive-log", methods=["POST"])
def receive_log():

    log = request.get_json()

    # =========================
    # HEARTBEAT HANDLER
    # =========================

    if log.get("type") == "heartbeat":

        update_heartbeat(
            generator_id=log["generator_id"],
            hostname=log["hostname"]
        )

        send_to_siem(log)

        print(
            f"Heartbeat received from {log['hostname']}"
        )

        return jsonify(
            {
                "status": "heartbeat_received",
                "generator_id": log["generator_id"],
                "hostname": log["hostname"]
            }
        ), 200

    return process_message(log)