from datetime import datetime

from database.replay_db import (
    event_exists,
    store_event
)


MAX_LOG_AGE_SECONDS = 300


def validate_timestamp(timestamp):
    """
    Validate that the collector timestamp is recent
    and not in the future.
    """

    try:

        print("\n========== TIMESTAMP DEBUG ==========")

        print(
            "[RECEIVED TIMESTAMP]:",
            timestamp
        )

        log_time = datetime.strptime(
            timestamp,
            "%d/%m/%Y %H:%M:%S"
        )

        current_time = datetime.now()

        age = (
            current_time - log_time
        ).total_seconds()

        print(
            "[LOG TIME]:",
            log_time
        )

        print(
            "[CURRENT TIME]:",
            current_time
        )

        print(
            "[AGE]:",
            age,
            "seconds"
        )

        print(
            "[MAX AGE]:",
            MAX_LOG_AGE_SECONDS,
            "seconds"
        )

        MAX_AGE = 300
        MAX_FUTURE_SKEW = 10  # Allow up to 10 seconds ahead

        age = (datetime.now() - log_time).total_seconds()

        if age > MAX_AGE:
            print("[TIMESTAMP RESULT]: EXPIRED TIMESTAMP")
            return False

        if age < -MAX_FUTURE_SKEW:
            print("[TIMESTAMP RESULT]: FUTURE TIMESTAMP")
            return False

        print("[TIMESTAMP RESULT]: VALID TIMESTAMP")
        return True


        if age > MAX_LOG_AGE_SECONDS:

            print(
                "[TIMESTAMP RESULT]: EXPIRED"
            )

            return False

        print(
            "[TIMESTAMP RESULT]: VALID"
        )

        print(
            "=====================================\n"
        )

        return True

    except Exception as exc:

        print(
            "[TIMESTAMP ERROR]:",
            exc
        )

        return False


def check_duplicate_event(log):
    """
    Check whether an event has already been processed.

    Returns:
        True  -> new event
        False -> duplicate event
    """

    event_id = log.get("event_id")

    if not event_id:

        print(
            "[REPLAY] Event has no event_id."
        )

        return False

    if event_exists(event_id):

        print(
            f"[REPLAY] Duplicate event detected: "
            f"{event_id}"
        )

        return False

    store_event(log)

    print(
        f"[REPLAY] New event stored: "
        f"{event_id}"
    )

    return True