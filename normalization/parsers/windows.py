import re
import json

from .base import BaseParser


class WindowsParser(BaseParser):











    def detect_event_type(self, message):

        # ------------------------------------
        # Real Windows Collector (dict)
        # ------------------------------------

        if isinstance(message, dict):

            event_id = message.get("event_id")

            event_map = {

                4624: "successful_login",

                4625: "failed_login",

                4634: "logoff",

                4648: "explicit_credentials",

                4672: "special_privileges_assigned",

                4688: "process_created",

                4689: "process_terminated",

                4697: "service_installed",

                4719: "audit_policy_changed",

                4720: "user_created",

                4723: "password_changed",

                4724: "password_reset",

                4726: "user_deleted",

                4732: "admin_privilege_granted",

                4740: "account_locked",

                4768: "kerberos_tgt_requested",

                4769: "kerberos_service_ticket",

                4771: "kerberos_pre_auth_failed",

                4776: "credential_validation",

                4798: "user_group_enumeration",

                4799: "group_membership_enumeration",

                5140: "network_share_access",

                5156: "firewall_connection_allowed",

                5157: "firewall_connection_blocked",

                5379: "credential_manager_read",

                5382: "credential_manager_export",

                1102: "audit_log_cleared"

            }

            return event_map.get(
                event_id,
                "unknown"
            )

        # ------------------------------------
        # Old Log Generator (text)
        # ------------------------------------

        msg = str(message).lower()

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

        if "4720" in msg:
            return "user_created"

        if "4726" in msg:
            return "user_deleted"

        if "4732" in msg:
            return "admin_privilege_granted"

        if "1102" in msg:
            return "audit_log_cleared"

        return "unknown"









    

    def detect_severity(self, message):

        # =====================================
        # Real Windows Event
        # =====================================

        if isinstance(message, dict):

            event_id = message.get("event_id")

            if event_id in [1102]:
                return "critical"

            if event_id in [4720, 4726, 4732]:
                return "high"

            if event_id in [4625, 4740, 4723, 4724]:
                return "medium"

            return "low"

        # =====================================
        # Generated Windows Log
        # =====================================

        msg = message.lower()

        # Critical

        if (
            "1102" in msg
            or "audit log cleared" in msg
            or "windows defender detected malware" in msg
            or "virus detected" in msg
            or "ransomware" in msg
        ):
            return "critical"

        # High

        if (
            "4720" in msg
            or "4726" in msg
            or "4732" in msg
            or "administrator privileges granted" in msg
            or "port scan" in msg
        ):
            return "high"

        # Medium

        if (
            "4625" in msg
            or "failed logon" in msg
            or "4740" in msg
            or "account locked" in msg
            or "4723" in msg
            or "4724" in msg
            or "password changed" in msg
            or "password reset" in msg
            or "firewall blocked" in msg
        ):
            return "medium"

        return "low"









    

    def extract_additional_fields(self, log):

        message = log["message"]
        if isinstance(message, dict):

            strings = message.get("strings", [])

            username = None

            for value in strings:

                if (
                    isinstance(value, str)
                    and value
                    and "\\\\" not in value
                    and value not in [
                        "SYSTEM",
                        "NT AUTHORITY",
                        "WORKGROUP"
                    ]
                    and not value.startswith("S-1-")
                ):

                    username = value
                    break

            return {

                "username": username,

                "source_ip": None,

                "service": "eventlog",

                "destination_port": None,

                "event_id": message.get("event_id"),

                "logon_type": None

            }

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