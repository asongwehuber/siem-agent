from .base import BaseParser

import json


class AndroidParser(BaseParser):

    def detect_event_type(self, message):

        msg = message.lower()

        # ==========================
        # Structured Application Security
        # ==========================

        try:
            data = json.loads(message)

            if data.get("event_type") == "application_security":
                return "application_security"

        except (json.JSONDecodeError, TypeError):
            pass

        # ==========================
        # Collector
        # ==========================

        if "android siem collector started" in msg:
            return "collector_startup"

        # ==========================
        # Authentication
        # ==========================

        if "failed password" in msg:
            return "failed_login"

        # ==========================
        # Network
        # ==========================

        if "port scan detected" in msg:
            return "port_scan"

        # ==========================
        # Application Security
        # ==========================

        if "suspicious application activity" in msg:
            return "suspicious_activity"

        # ==========================
        # Application Management
        # ==========================

        if "application installed" in msg:
            return "app_installed"

        if "application uninstalled" in msg:
            return "app_uninstalled"

        return "unknown"

    def detect_severity(self, message):

        msg = message.lower()

        # ==========================
        # Structured Application Security
        # ==========================

        try:
            data = json.loads(message)

            if data.get("event_type") == "application_security":

                severity = data.get("severity")

                if severity:
                    return severity.lower()

        except (json.JSONDecodeError, TypeError):
            pass

        # ==========================
        # High
        # ==========================

        if "port scan detected" in msg:
            return "high"

        # ==========================
        # Medium
        # ==========================

        if "failed password" in msg:
            return "medium"

        if "suspicious application activity" in msg:
            return "medium"

        if "application uninstalled" in msg:
            return "medium"

        # ==========================
        # Low
        # ==========================

        return "low"

    def extract_additional_fields(self, log):

        message = log["message"]

        source_ip = self.extract_ip(message)

        destination_port = self.extract_port(message)

        username = self.extract_username(message)

        return {
            "source_ip": source_ip,
            "username": username,
            "service": "android",
            "destination_port": destination_port
        }

    def validate(self, normalized_log):

        validation = super().validate(
            normalized_log
        )

        errors = validation["errors"]

        event_type = normalized_log.get(
            "event_type"
        )

        # ==========================
        # Username validation
        # ==========================

        username_required = {
            "failed_login"
        }

        self.validate_required_field(
            normalized_log,
            "username",
            username_required,
            errors,
            "Android username not detected"
        )

        # ==========================
        # Source IP validation
        # ==========================

        ip_required = {
            "failed_login",
            "port_scan"
        }

        self.validate_required_field(
            normalized_log,
            "source_ip",
            ip_required,
            errors,
            "Android source IP not detected"
        )

        validation["valid"] = len(errors) == 0

        return validation