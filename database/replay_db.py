import sqlite3
from pathlib import Path


DATABASE_FILE = Path(
    "database/events.db"
)



def initialize_database():

    connection = sqlite3.connect(
        DATABASE_FILE
    )

    cursor = connection.cursor()


    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS processed_events
        (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            event_id TEXT UNIQUE NOT NULL,

            generator_id TEXT,

            hostname TEXT,

            timestamp TEXT,

            received_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )


    connection.commit()

    connection.close()



def event_exists(event_id):

    connection = sqlite3.connect(
        DATABASE_FILE
    )

    cursor = connection.cursor()


    cursor.execute(
        """
        SELECT event_id
        FROM processed_events
        WHERE event_id = ?
        """,
        (event_id,)
    )


    result = cursor.fetchone()


    connection.close()


    return result is not None



def store_event(log):

    connection = sqlite3.connect(
        DATABASE_FILE
    )

    cursor = connection.cursor()


    cursor.execute(
        """
        INSERT INTO processed_events
        (
            event_id,
            generator_id,
            hostname,
            timestamp
        )

        VALUES (?, ?, ?, ?)
        """,

        (
            log["event_id"],
            log["generator_id"],
            log["hostname"],
            log["timestamp"]
        )
    )


    connection.commit()

    connection.close()