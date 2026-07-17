import requests
from config import SIEM_ENDPOINT


def send_to_siem(log):

    try:

        response = requests.post(
            SIEM_ENDPOINT,
            json=log,
            timeout=5
        )


        return response.json()


    except Exception as error:

        return {
            "status": "error",
            "message": str(error)
        }