import re

from .base import BaseParser


class WindowsParser(BaseParser):

    def detect_event_type(self, message):

        msg = message.lower()

        # ==========================
        # Authentication
        # ==========================

        if "4624" in msg or "successful logon" in msg:
            return "successful_login"

        if "4625" in msg or "failed logon" in msg:
            return "failed_login"

        if "4740" in msg or "account locked" in msg:
            return "account_locked"

        if "4723" in msg or "password changed" in msg:
            return "password_changed"

        if "4724" in msg or "password reset" in msg:
            return "password_reset"

        # ==========================
        # User Management
        # ==========================

        if "4720" in msg or "user account created" in msg:
            return "user_created"

        if "4726" in msg or "user account deleted" in msg:
            return "user_deleted"

        if "4732" in msg or "administrator privileges granted" in msg:
            return "admin_privilege_granted"

        # ==========================
        # Security
        # ==========================

        if "1102" in msg or "audit log cleared" in msg:
            return "log_cleared"

        # ==========================
        # Malware
        # ==========================

        if (
            "windows defender detected malware" in msg
            or
            "virus detected" in msg
        ):
            return "malware_detected"

        if "ransomware" in msg:
            return "ransomware_detected"

        # ==========================
        # Network
        # ==========================

        if "firewall blocked" in msg:
            return "firewall_block"

        if "port scan" in msg:
            return "port_scan"

        # ==========================
        # System
        # ==========================

        if "system reboot" in msg:
            return "system_reboot"

        if "service started" in msg:
            return "service_started"

        if "service stopped" in msg:
            return "service_stopped"

        return "unknown"

    def detect_severity(self, message):

        msg = message.lower()

        # Critical

        if (
            "1102" in msg
            or
            "audit log cleared" in msg
            or
            "windows defender detected malware" in msg
            or
            "virus detected" in msg
            or
            "ransomware" in msg
        ):
            return "critical"

        # High

        if (
            "4720" in msg
            or
            "4726" in msg
            or
            "4732" in msg
            or
            "administrator privileges granted" in msg
            or
            "port scan" in msg
        ):
            return "high"

        # Medium

        if (
            "4625" in msg
            or
            "failed logon" in msg
            or
            "4740" in msg
            or
            "account locked" in msg
            or
            "4723" in msg
            or
            "4724" in msg
            or
            "password changed" in msg
            or
            "password reset" in msg
            or
            "firewall blocked" in msg
        ):
            return "medium"

        return "low"

    def extract_additional_fields(self, log):

        message = log["message"]

        # Reuse BaseParser helpers

        username = self.extract_username(message)
        source_ip = self.extract_ip(message)
        destination_port = self.extract_port(message)

        service = "unknown"
        event_id = None
        logon_type = None

        # ==========================
        # Event ID
        # ==========================

        event_match = re.search(
            r"EventID[:=]?\s*(\d+)",
            message,
            re.IGNORECASE
        )

        if event_match:

            event_id = int(
                event_match.group(1)
            )

        # ==========================
        # Logon Type
        # ==========================

        logon_match = re.search(
            r"Logon Type[:=]\s*(\d+)",
            message,
            re.IGNORECASE
        )

        if logon_match:

            logon_type = int(
                logon_match.group(1)
            )

        # ==========================
        # Windows Services
        # ==========================

        lower = message.lower()

        services = {

            "defender": "windows_defender",

            "firewall": "windows_firewall",

            "eventlog": "eventlog"

        }

        for keyword, value in services.items():

            if keyword in lower:

                service = value

                break

        return {

            "username": username,

            "source_ip": source_ip,

            "service": service,

            "destination_port": destination_port,

            "event_id": event_id,

            "logon_type": logon_type

        }

    def validate(self, normalized_log):

        validation = super().validate(
            normalized_log
        )

        errors = validation["errors"]

        username_required = {

            "successful_login",

            "failed_login",

            "account_locked",

            "password_changed",

            "password_reset",

            "user_created",

            "user_deleted",

            "admin_privilege_granted"

        }

        self.validate_required_field(

            normalized_log,

            "username",

            username_required,

            errors,

            "Windows username not detected"

        )

        ip_required = {

            "successful_login",

            "failed_login",

            "port_scan"

        }

        self.validate_required_field(

            normalized_log,

            "source_ip",

            ip_required,

            errors,

            "Windows source IP not detected"

        )

        validation["valid"] = len(errors) == 0

        return validation