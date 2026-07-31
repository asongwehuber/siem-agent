import requests

from config import (
    SIEM_LOG_ENDPOINT,
    SIEM_HEARTBEAT_ENDPOINT
)


def send_to_siem(data):
    """
    Forward logs or heartbeats to the Mini-SIEM.
    """

    endpoint = (
        SIEM_HEARTBEAT_ENDPOINT
        if data.get("type") == "heartbeat"
        else SIEM_LOG_ENDPOINT
    )

    try:

        response = requests.post(
            endpoint,
            json=data,
            timeout=5
        )

        return response.json()

    except Exception as error:

        return {
            "status": "error",
            "message": str(error)
        }