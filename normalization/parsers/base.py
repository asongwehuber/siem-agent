import re


class BaseParser:
    """
    Base parser shared by all log source parsers.
    Provides common extraction and validation helpers.
    """

    # =====================================================
    # Common Extraction Helpers
    # =====================================================

    def extract_ip(self, message):

        ips = re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            message
        )

        if ips:
            return ips[0]

        return "unknown"

    def extract_ips(self, message):

        return re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            message
        )

    def extract_port(self, message):

        port_match = re.search(
            r"(?:port\s+|:)(\d{2,5})",
            message,
            re.IGNORECASE
        )

        if port_match:
            return int(port_match.group(1))

        return None

    def extract_username(self, message):

        patterns = [

            r"user=([A-Za-z0-9._-]+)",

            r"User=([A-Za-z0-9._-]+)",

            r"Account Name[:=]\s*([^\s]+)",

            r"Accepted password for\s+([A-Za-z0-9._-]+)",

            r"Failed password for\s+([A-Za-z0-9._-]+)",

            r"invalid user\s+([A-Za-z0-9._-]+)"

        ]

        for pattern in patterns:

            match = re.search(
                pattern,
                message,
                re.IGNORECASE
            )

            if match:
                return match.group(1)

        return "unknown"

    def extract_database(self, message):

        match = re.search(
            r"database=([A-Za-z0-9_-]+)",
            message,
            re.IGNORECASE
        )

        if match:
            return match.group(1)

        return "unknown"

    def extract_query_type(self, message):

        match = re.search(
            r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|GRANT)\b",
            message,
            re.IGNORECASE
        )

        if match:
            return match.group(1).upper()

        return None

    def extract_protocol(self, message):

        match = re.search(
            r"\b(TCP|UDP|ICMP)\b",
            message,
            re.IGNORECASE
        )

        if match:
            return match.group(1).upper()

        return "unknown"

    # =====================================================
    # Default Fields
    # =====================================================

    def default_fields(self):

        return {

            "source_ip": "unknown",

            "hostname": None,

            "event_type": "unknown",

            "severity": "low",

            "destination_port": None,

            "message": ""

        }

    # =====================================================
    # Event Detection
    # =====================================================

    def detect_event_type(self, message):

        return "unknown"

    def detect_severity(self, message):

        return "low"

    # =====================================================
    # Normalization
    # =====================================================

    def normalize(self, log):

        message = log["message"]

        normalized = self.default_fields()

        normalized.update({

            "source_ip": self.extract_ip(message),

            "hostname": log["hostname"],

            "event_type": self.detect_event_type(message),

            "severity": self.detect_severity(message),

            "destination_port": self.extract_port(message),

            "message": message

        })

        normalized.update(
            self.extract_additional_fields(log)
        )

        return normalized

    def extract_additional_fields(self, log):

        return {}

    # =====================================================
    # Validation Helpers
    # =====================================================

    def validate_required_field(
        self,
        normalized_log,
        field_name,
        required_events,
        errors,
        error_message
    ):

        if (

            normalized_log.get("event_type") in required_events

            and

            (
                normalized_log.get(field_name) in (
                    None,
                    "",
                    "unknown"
                )
            )

        ):

            errors.append(error_message)

    # =====================================================
    # Validation
    # =====================================================

    def validate(self, normalized_log):

        errors = []

        if not normalized_log.get("hostname"):

            errors.append(
                "Missing hostname"
            )

        if not normalized_log.get("message"):

            errors.append(
                "Missing message"
            )

        if normalized_log.get("event_type") == "unknown":

            errors.append(
                "Unknown event type"
            )

        return {

            "valid": len(errors) == 0,

            "errors": errors

        }