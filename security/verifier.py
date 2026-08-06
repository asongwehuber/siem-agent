import json
import hashlib
import hmac

from config import SECRET_KEY


def generate_signature(
    timestamp,
    event_id,
    generator_id,
    hostname,
    message
):
    """
    Generate HMAC-SHA256 signature.
    """

    if isinstance(message, dict):

        message = json.dumps(

            message,

            sort_keys=True,

            separators=(",", ":")

        )

    data = (
        f"{timestamp}|"
        f"{event_id}|"
        f"{generator_id}|"
        f"{hostname}|"
        f"{message}"
    )

    return hmac.new(
        SECRET_KEY.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest()


def verify_signature(log):
    """
    Verify received log signature.
    """

    expected_signature = generate_signature(
        log["timestamp"],
        log["event_id"],
        log["generator_id"],
        log["hostname"],
        log["message"]
    )

    return hmac.compare_digest(
        expected_signature,
        log["signature"]
    )