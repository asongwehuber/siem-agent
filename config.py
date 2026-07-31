import os

from dotenv import load_dotenv

load_dotenv()


SECRET_KEY = os.getenv("SECRET_KEY")


AGENT_HOST = os.getenv(
    "AGENT_HOST",
    "0.0.0.0"
)


AGENT_PORT = int(
    os.getenv(
        "AGENT_PORT",
        6000
    )
)


SIEM_LOG_ENDPOINT = os.getenv(
    "SIEM_LOG_ENDPOINT",
    "http://127.0.0.1:5000/submit-log"
)


SIEM_HEARTBEAT_ENDPOINT = os.getenv(
    "SIEM_HEARTBEAT_ENDPOINT",
    "http://127.0.0.1:5000/submit-heartbeat"
)


AGENT_ID = os.getenv(
    "AGENT_ID",
    "AGENT-001"
)