import re

from .base import BaseParser


class ApacheParser(BaseParser):

    def detect_event_type(self, message):

        msg = message.lower()

        # ==========================
        # HTTP Methods
        # ==========================

        if "post " in msg:
            return "http_post"

        if "get " in msg:
            return "http_request"

        # ==========================
        # Authentication
        # ==========================

        if "login successful" in msg:
            return "successful_login"

        if "login failed" in msg:
            return "failed_login"

        # ==========================
        # Web Attacks
        # ==========================

        if "sql injection" in msg:
            return "sql_injection"

        if "xss" in msg:
            return "xss_attack"

        if "directory traversal" in msg:
            return "directory_traversal"

        if "file upload" in msg:
            return "file_upload"

        if "request flood" in msg:
            return "request_flood"

        # ==========================
        # HTTP Status
        # ==========================

        if "401" in msg:
            return "authentication_failed"

        if "403" in msg:
            return "access_forbidden"

        if "404" in msg:
            return "not_found"

        if "500" in msg:
            return "server_error"

        # ==========================
        # Service
        # ==========================

        if "apache service started" in msg:
            return "service_started"

        if "apache service stopped" in msg:
            return "service_stopped"

        return "http_request"

    def detect_severity(self, message):

        msg = message.lower()

        # Critical

        if (
            "sql injection" in msg
            or
            "request flood" in msg
        ):
            return "critical"

        # High

        if (
            "xss" in msg
            or
            "directory traversal" in msg
            or
            "500" in msg
        ):
            return "high"

        # Medium

        if (
            "401" in msg
            or
            "403" in msg
            or
            "login failed" in msg
            or
            "file upload" in msg
        ):
            return "medium"

        return "low"

    def extract_additional_fields(self, log):

        message = log["message"]

        # Reuse BaseParser helpers

        source_ip = self.extract_ip(message)
        username = self.extract_username(message)
        destination_port = self.extract_port(message)

        service = "apache"
        http_method = None
        url = None
        status_code = None
        user_agent = "unknown"

        # ==========================
        # HTTP Method
        # ==========================

        method_match = re.search(
            r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b",
            message,
            re.IGNORECASE
        )

        if method_match:

            http_method = method_match.group(1).upper()

        # ==========================
        # URL
        # ==========================

        url_match = re.search(
            r"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)",
            message,
            re.IGNORECASE
        )

        if url_match:

            url = url_match.group(2)

        # ==========================
        # Status Code
        # ==========================

        status_match = re.search(
            r"\b(200|201|301|302|400|401|403|404|500|503)\b",
            message
        )

        if status_match:

            status_code = int(
                status_match.group(1)
            )

        # ==========================
        # User Agent
        # ==========================

        agent_match = re.search(
            r'User-Agent[:=]\s*"([^"]+)"',
            message,
            re.IGNORECASE
        )

        if agent_match:

            user_agent = agent_match.group(1)

        return {

            "source_ip": source_ip,

            "username": username,

            "service": service,

            "destination_port": destination_port,

            "http_method": http_method,

            "url": url,

            "status_code": status_code,

            "user_agent": user_agent

        }

    def validate(self, normalized_log):

        validation = super().validate(
            normalized_log
        )

        errors = validation["errors"]

        ip_required = {

            "http_request",

            "http_post",

            "successful_login",

            "failed_login",

            "sql_injection",

            "xss_attack",

            "directory_traversal",

            "request_flood"

        }

        self.validate_required_field(

            normalized_log,

            "source_ip",

            ip_required,

            errors,

            "Apache source IP not detected"

        )

        method_required = {

            "http_request",

            "http_post",

            "sql_injection",

            "xss_attack",

            "directory_traversal"

        }

        self.validate_required_field(

            normalized_log,

            "http_method",

            method_required,

            errors,

            "HTTP method not detected"

        )

        url_required = {

            "http_request",

            "http_post",

            "sql_injection",

            "xss_attack",

            "directory_traversal"

        }

        self.validate_required_field(

            normalized_log,

            "url",

            url_required,

            errors,

            "URL not detected"

        )

        validation["valid"] = len(errors) == 0

        return validation