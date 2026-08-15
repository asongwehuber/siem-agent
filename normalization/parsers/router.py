from .base import BaseParser


class RouterParser(BaseParser):
    """
    Parser for MTN HomeBox router network activity logs.
    """

    def detect_event_type(self, message):
        if isinstance(message, dict):
            event_type = message.get("event_type")

            if event_type:
                return event_type

            return "network_activity"

        return "network_activity"

    def detect_severity(self, message):
        """
        Router network activity is informational by default.

        The detection engine can later raise severity if the
        event matches an actual security rule.
        """
        return "low"

    def extract_additional_fields(self, log):
        message = log.get("message", {})

        if not isinstance(message, dict):
            return {
                "source_ip": self.extract_ip(message),
                "destination_port": self.extract_port(message)
            }

        details = message.get("details", {})

        if not isinstance(details, dict):
            details = {}

        source_ip = (
            details.get("ipv4addr")
            or details.get("ipv6addr")
            or "unknown"
        )

        return {
            "source_ip": source_ip,
            "username": "unknown",
            "service": "router",
            "destination_port": None
        }

    def validate(self, normalized_log):
        validation = super().validate(normalized_log)

        return validation