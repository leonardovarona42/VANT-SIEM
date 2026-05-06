from .base import BaseParser
from .firewall_huawei import HuaweiFirewallParser
from .snort import SnortParser
from .suricata import SuricataParser
from .windows_ad import WindowsADParser
from .windows_dhcp import WindowsDHCPParser
from .windows_dns import WindowsDNSParser
from .samba import SambaParser
from .generic_syslog import GenericSyslogParser

PARSER_REGISTRY = {
    'firewall_huawei': HuaweiFirewallParser,
    'snort': SnortParser,
    'suricata': SuricataParser,
    'windows_ad': WindowsADParser,
    'windows_dhcp': WindowsDHCPParser,
    'windows_dns': WindowsDNSParser,
    'samba': SambaParser,
    'generic_syslog': GenericSyslogParser,
}

def get_parser(source_type):
    cls = PARSER_REGISTRY.get(source_type)
    if cls is None:
        return GenericSyslogParser()
    return cls()
