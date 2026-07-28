from receiver import app

from config import AGENT_HOST, AGENT_PORT

from database.replay_db import initialize_database

from services.heartbeat_monitor import (
    start_heartbeat_monitor
)


initialize_database()

# Start heartbeat monitor
start_heartbeat_monitor()


if __name__ == "__main__":

    app.run(
        host=AGENT_HOST,
        port=AGENT_PORT,
        debug=True
    )