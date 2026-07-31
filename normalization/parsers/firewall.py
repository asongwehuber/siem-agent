import re

from .base import BaseParser


class FirewallParser(BaseParser):

    def detect_event_type(self, message):

        msg = message.lower()

        # ==========================
        # Connections
        # ==========================

        if "connection allowed" in msg or "allowed" in msg:
            return "allowed_connection"

        if "connection blocked" in msg or "blocked" in msg:
            return "blocked_connection"

        if "connection dropped" in msg or "dropped" in msg:
            return "dropped_connection"

        # ==========================
        # Threat Detection
        # ==========================

        if "port scan" in msg:
            return "port_scan"

        if "ddos" in msg or "request flood" in msg:
            return "ddos_attack"

        if "malware traffic" in msg:
            return "malware_traffic"

        # ==========================
        # DNS
        # ==========================

        if "dns query" in msg:
            return "dns_request"

        # ==========================
        # VPN
        # ==========================

        if "vpn connected" in msg:
            return "vpn_connected"

        if "vpn disconnected" in msg:
            return "vpn_disconnected"

        # ==========================
        # Configuration
        # ==========================

        if "rule modified" in msg:
            return "rule_modified"

        # ==========================
        # Service
        # ==========================

        if "firewall started" in msg:
            return "service_started"

        if "firewall stopped" in msg:
            return "service_stopped"

        return "network_event"

    def detect_severity(self, message):

        msg = message.lower()

        # Critical

        if (
            "ddos" in msg
            or
            "request flood" in msg
            or
            "malware traffic" in msg
        ):
            return "critical"

        # High

        if (
            "port scan" in msg
            or
            "rule modified" in msg
        ):
            return "high"

        # Medium

        if (
            "blocked" in msg
            or
            "dropped" in msg
            or
            "vpn disconnected" in msg
        ):
            return "medium"

        return "low"

    def extract_additional_fields(self, log):

        message = log["message"]

        # Reuse BaseParser helpers

        source_ip = self.extract_ip(message)
        destination_port = self.extract_port(message)

        destination_ip = "unknown"
        protocol = "unknown"
        action = "unknown"
        service = "firewall"

        # ==========================
        # Destination IP
        # ==========================

        ips = re.findall(
            r"(\d{1,3}(?:\.\d{1,3}){3})",
            message
        )

        if len(ips) >= 2:

            destination_ip = ips[1]

        # ==========================
        # Protocol
        # ==========================

        proto_match = re.search(
            r"\b(TCP|UDP|ICMP)\b",
            message,
            re.IGNORECASE
        )

        if proto_match:

            protocol = proto_match.group(1).upper()

        # ==========================
        # Action
        # ==========================

        lower = message.lower()

        actions = {

            "allowed": "allowed",

            "blocked": "blocked",

            "dropped": "dropped"

        }

        for keyword, value in actions.items():

            if keyword in lower:

                action = value

                break

        return {

            "source_ip": source_ip,

            "destination_ip": destination_ip,

            "destination_port": destination_port,

            "protocol": protocol,

            "action": action,

            "service": service

        }

    def validate(self, normalized_log):

        validation = super().validate(
            normalized_log
        )

        errors = validation["errors"]

        ip_required = {

            "allowed_connection",

            "blocked_connection",

            "dropped_connection",

            "port_scan",

            "ddos_attack",

            "malware_traffic"

        }

        self.validate_required_field(

            normalized_log,

            "source_ip",

            ip_required,

            errors,

            "Firewall source IP not detected"

        )

        protocol_required = {

            "allowed_connection",

            "blocked_connection",

            "dropped_connection"

        }

        self.validate_required_field(

            normalized_log,

            "protocol",

            protocol_required,

            errors,

            "Network protocol not detected"

        )

        validation["valid"] = len(errors) == 0

        return validation