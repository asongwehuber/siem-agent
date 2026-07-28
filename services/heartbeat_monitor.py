import threading
import time
from datetime import datetime, timedelta

from database.heartbeat_db import (
    get_all_machines,
    mark_offline,
    has_offline_alert,
    offline_alert_sent
)

from sender import send_to_siem


CHECK_INTERVAL = 5      # seconds
OFFLINE_TIMEOUT = 30    # seconds


def monitor_loop():
    """
    Continuously monitor all registered machines and
    generate one offline alert when a heartbeat expires.
    """

    print("[Heartbeat Monitor] Started")

    while True:

        now = datetime.now()

        machines = get_all_machines()

        for generator_id, machine in machines.items():

            elapsed = now - machine["last_seen"]
            

            print("=" * 60)
            print("Machine:", machine["hostname"])
            print("Current Time :", now)
            print("Last Seen    :", machine["last_seen"])
            print("Elapsed      :", elapsed)
            print("=" * 60)





            if elapsed > timedelta(seconds=OFFLINE_TIMEOUT):

                if not has_offline_alert(generator_id):

                    print(
                        f"[Heartbeat Monitor] "
                        f"{machine['hostname']} is OFFLINE"
                    )

                    mark_offline(generator_id)

                    alert = {

                        "source_ip": None,

                        "hostname": machine["hostname"],

                        "event_type": "machine_offline",

                        "event_category": "availability",

                        "destination_port": None,

                        "severity": "high",

                        "message":
                            f"{machine['hostname']} "
                            f"has not sent a heartbeat for "
                            f"{int(elapsed.total_seconds())} seconds."

                    }

                    send_to_siem(alert)

                    offline_alert_sent(generator_id)

        time.sleep(CHECK_INTERVAL)


def start_heartbeat_monitor():
    """
    Starts the monitor as a daemon thread.
    """

    thread = threading.Thread(
        target=monitor_loop,
        daemon=True
    )

    thread.start()

    return thread