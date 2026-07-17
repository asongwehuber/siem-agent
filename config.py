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


SIEM_ENDPOINT = os.getenv(
    "SIEM_ENDPOINT",
    "http://127.0.0.1:5000/submit-log"
)


AGENT_ID = os.getenv(
    "AGENT_ID",
    "AGENT-001"
)