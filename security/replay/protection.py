from datetime import datetime

from database.replay_db import (
    event_exists,
    store_event
)


MAX_LOG_AGE_SECONDS = 300



def validate_timestamp(timestamp):

    try:

        log_time = datetime.strptime(
            timestamp,
            "%d/%m/%Y %H:%M:%S"
        )


        current_time = datetime.now()


        age = (
            current_time - log_time
        ).total_seconds()


        if age < 0:
            return False


        if age > MAX_LOG_AGE_SECONDS:
            return False


        return True


    except Exception:

        return False




def check_duplicate_event(log):

    event_id = log["event_id"]


    if event_exists(event_id):

        return False


    store_event(log)


    return True