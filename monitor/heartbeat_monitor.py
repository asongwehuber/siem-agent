import time
from datetime import datetime

from database.heartbeat_db import (
    get_all_machines,
    mark_offline,
    mark_online,
    has_offline_alert,
    offline_alert_sent
)


HEARTBEAT_TIMEOUT = 30      # seconds
CHECK_INTERVAL = 5          # seconds


def start_monitor():

    print("[Heartbeat Monitor] Started")

    while True:

        now = datetime.now()

        machines = get_all_machines()

        for generator_id, machine in machines.items():

            elapsed = (
                now - machine["last_seen"]
            ).total_seconds()

            if elapsed > HEARTBEAT_TIMEOUT:

                if machine["status"] != "offline":

                    print(
                        f"[OFFLINE] {machine['hostname']}"
                    )

                    mark_offline(generator_id)

                if not has_offline_alert(generator_id):

                    print(
                        f"[ALERT] {machine['hostname']} heartbeat missing"
                    )

                    # We will forward this to the Mini-SIEM
                    # in the next step.

                    offline_alert_sent(generator_id)

            else:

                if machine["status"] != "online":

                    print(
                        f"[ONLINE] {machine['hostname']}"
                    )

                    mark_online(generator_id)

        time.sleep(CHECK_INTERVAL)