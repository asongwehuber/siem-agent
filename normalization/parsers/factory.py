from .linux import LinuxParser
from .windows import WindowsParser
from .apache import ApacheParser
from .firewall import FirewallParser
from .mysql import MySQLParser


PARSERS = {

    "LINUX": LinuxParser(),

    "WINDOWS": WindowsParser(),

    "APACHE": ApacheParser(),

    "FIREWALL": FirewallParser(),

    "MYSQL": MySQLParser()

}


def get_parser(generator_id):
    """
    Returns the appropriate parser based on
    the generator ID.
    """

    source = generator_id.split("-")[0].upper()

    return PARSERS.get(
        source,
        LinuxParser()      # default parser
    )