import re

from .base import BaseParser


class LinuxParser(BaseParser):

    def detect_event_type(self, message):

        msg = message.lower()

        # ==========================
        # Authentication
        # ==========================

        if "accepted password" in msg:
            return "successful_login"

        if "failed password" in msg:
            return "failed_login"

        if "invalid user" in msg:
            return "invalid_user_login"

        if "user account" in msg and "locked" in msg:
            return "account_locked"

        if "password expired" in msg:
            return "password_expired"

        if "session opened" in msg:
            return "session_opened"

        if "session closed" in msg:
            return "session_closed"

        # ==========================
        # Privilege Escalation
        # ==========================

        if "sudo" in msg:
            return "sudo_command"

        if "su root" in msg:
            return "privilege_escalation"

        # ==========================
        # User Management
        # ==========================

        if "new user" in msg:
            return "user_created"

        if "useradd" in msg:
            return "user_created"

        if "userdel" in msg:
            return "user_deleted"

        if "usermod" in msg:
            return "user_modified"

        if "groupadd" in msg:
            return "group_created"

        # ==========================
        # Network
        # ==========================

        if "port scan" in msg:
            return "port_scan"

        if "connection refused" in msg:
            return "connection_refused"

        # ==========================
        # Malware
        # ==========================

        if (
            "malware detected" in msg
            or
            "virus detected" in msg
        ):
            return "malware_detected"

        if "ransomware" in msg:
            return "ransomware_detected"

        # ==========================
        # System
        # ==========================

        if "kernel panic" in msg:
            return "kernel_panic"

        if "disk usage" in msg:
            return "disk_full"

        if "cpu usage" in msg:
            return "cpu_high"

        if "memory usage" in msg:
            return "memory_high"

        if "cron" in msg:
            return "scheduled_task"

        return "unknown"

    def detect_severity(self, message):

        msg = message.lower()

        # Critical

        if (
            "malware detected" in msg
            or
            "virus detected" in msg
            or
            "ransomware" in msg
            or
            "kernel panic" in msg
        ):
            return "critical"

        # High

        if (
            "port scan" in msg
            or
            "useradd" in msg
            or
            "new user" in msg
            or
            "disk usage" in msg
            or
            "privilege escalation" in msg
        ):
            return "high"

        # Medium

        if (
            "failed password" in msg
            or
            "sudo" in msg
            or
            ("user account" in msg and "locked" in msg)
            or
            "password expired" in msg
            or
            "connection refused" in msg
            or
            "cpu usage" in msg
            or
            "memory usage" in msg
        ):
            return "medium"

        return "low"

    def extract_additional_fields(self, log):

        message = log["message"]

        # Reuse BaseParser helpers
        source_ip = self.extract_ip(message)
        destination_port = self.extract_port(message)
        username = self.extract_username(message)

        service = "unknown"

        # Linux-specific username patterns not covered by BaseParser

        patterns = [

            r"sudo authentication failure for\s+([A-Za-z0-9._-]+)",

            r"New user\s+([A-Za-z0-9._-]+)",

            r"User account\s+([A-Za-z0-9._-]+)\s+locked",

            r"useradd.*?([A-Za-z0-9._-]+)",

            r"userdel.*?([A-Za-z0-9._-]+)"

        ]

        if username == "unknown":

            for pattern in patterns:

                match = re.search(
                    pattern,
                    message,
                    re.IGNORECASE
                )

                if match:

                    username = match.group(1)

                    break

        # Linux services

        lower = message.lower()

        services = {

            "sshd": "sshd",

            "sudo": "sudo",

            "cron": "cron",

            "useradd": "useradd",

            "userdel": "userdel",

            "kernel": "kernel"

        }

        for keyword, value in services.items():

            if keyword in lower:

                service = value

                break

        return {

            "source_ip": source_ip,

            "username": username,

            "service": service,

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

        username_required = {

            "successful_login",

            "failed_login",

            "invalid_user_login",

            "sudo_command",

            "user_created",

            "user_deleted",

            "account_locked"

        }

        self.validate_required_field(

            normalized_log,

            "username",

            username_required,

            errors,

            "Linux username not detected"

        )

        ip_required = {

            "successful_login",

            "failed_login",

            "invalid_user_login",

            "port_scan"

        }

        self.validate_required_field(

            normalized_log,

            "source_ip",

            ip_required,

            errors,

            "Linux source IP not detected"

        )

        validation["valid"] = len(errors) == 0

        return validation