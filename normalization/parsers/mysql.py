from .base import BaseParser


class MySQLParser(BaseParser):

    def detect_event_type(self, message):

        msg = message.lower()

        # ==========================
        # Authentication
        # ==========================

        if "authenticated" in msg:
            return "successful_login"

        if "access denied" in msg:
            return "failed_login"

        # ==========================
        # Database Activity
        # ==========================

        if "suspicious query detected" in msg:
            return "suspicious_query"

        if "large data export detected" in msg:
            return "data_exfiltration"

        if "privilege escalation attempt" in msg:
            return "privilege_escalation"

        # ==========================
        # Database Operations
        # ==========================

        if "database created" in msg:
            return "database_created"

        if "database deleted" in msg:
            return "database_deleted"

        if "table created" in msg:
            return "table_created"

        if "table deleted" in msg:
            return "table_deleted"

        # ==========================
        # Backup
        # ==========================

        if "backup completed" in msg:
            return "backup_completed"

        if "backup failed" in msg:
            return "backup_failed"

        # ==========================
        # Replication
        # ==========================

        if "replication error" in msg:
            return "replication_error"

        # ==========================
        # Service
        # ==========================

        if "mysql service started" in msg:
            return "service_started"

        if "mysql service stopped" in msg:
            return "service_stopped"

        return "database_event"

    def detect_severity(self, message):

        msg = message.lower()

        # Critical

        if (
            "large data export detected" in msg
            or
            "privilege escalation attempt" in msg
        ):
            return "critical"

        # High

        if (
            "suspicious query detected" in msg
            or
            "backup failed" in msg
            or
            "replication error" in msg
            or
            "database deleted" in msg
        ):
            return "high"

        # Medium

        if (
            "access denied" in msg
            or
            "failed login" in msg
            or
            "table deleted" in msg
            or
            "database created" in msg
        ):
            return "medium"

        return "low"

    def extract_additional_fields(self, log):

        message = log["message"]

        # Reuse BaseParser helpers

        username = self.extract_username(message)
        source_ip = self.extract_ip(message)
        database = self.extract_database(message)
        query_type = self.extract_query_type(message)

        return {

            "username": username,

            "source_ip": source_ip,

            "database": database,

            "service": "mysql",

            "destination_port": None,

            "query_type": query_type

        }

    def validate(self, normalized_log):

        validation = super().validate(
            normalized_log
        )

        errors = validation["errors"]

        username_required = {

            "successful_login",

            "failed_login",

            "suspicious_query",

            "privilege_escalation",

            "data_exfiltration"

        }

        self.validate_required_field(

            normalized_log,

            "username",

            username_required,

            errors,

            "MySQL username not detected"

        )

        ip_required = {

            "successful_login",

            "failed_login"

        }

        self.validate_required_field(

            normalized_log,

            "source_ip",

            ip_required,

            errors,

            "MySQL source IP not detected"

        )

        database_required = {

            "data_exfiltration",

            "privilege_escalation",

            "database_created",

            "database_deleted"

        }

        self.validate_required_field(

            normalized_log,

            "database",

            database_required,

            errors,

            "Database name not detected"

        )

        query_required = {

            "suspicious_query"

        }

        self.validate_required_field(

            normalized_log,

            "query_type",

            query_required,

            errors,

            "SQL query type not detected"

        )

        validation["valid"] = len(errors) == 0

        return validation