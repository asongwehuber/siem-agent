from datetime import datetime
from threading import Lock

# Thread-safe storage
_lock = Lock()

# Structure:
# {
#   "LINUX-001": {
#       "generator_id": "LINUX-001",
#       "hostname": "Linux-Server-01",
#       "last_seen": datetime,
#       "status": "online",
#       "offline_alert_sent": False
#   }
# }
_machines = {}


def update_heartbeat(generator_id, hostname):
    """
    Create or update a machine heartbeat.
    """

    with _lock:

        _machines[generator_id] = {
            "generator_id": generator_id,
            "hostname": hostname,
            "last_seen": datetime.now(),
            "status": "online",
            "offline_alert_sent": False
        }


def get_machine(generator_id):
    with _lock:
        return _machines.get(generator_id)


def get_all_machines():
    with _lock:
        return dict(_machines)


def mark_offline(generator_id):
    with _lock:
        if generator_id in _machines:
            _machines[generator_id]["status"] = "offline"


def mark_online(generator_id):
    with _lock:
        if generator_id in _machines:
            _machines[generator_id]["status"] = "online"
            _machines[generator_id]["offline_alert_sent"] = False


def offline_alert_sent(generator_id):
    with _lock:
        if generator_id in _machines:
            _machines[generator_id]["offline_alert_sent"] = True


def has_offline_alert(generator_id):
    with _lock:
        machine = _machines.get(generator_id)
        if not machine:
            return False
        return machine["offline_alert_sent"]