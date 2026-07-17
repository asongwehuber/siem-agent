from receiver import app

from config import AGENT_HOST, AGENT_PORT

from database.replay_db import initialize_database


# Initialize persistent replay database
initialize_database()


if __name__ == "__main__":

    app.run(
        host=AGENT_HOST,
        port=AGENT_PORT,
        debug=True
    )