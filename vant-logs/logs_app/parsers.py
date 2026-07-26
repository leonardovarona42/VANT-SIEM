import logging
import re
from datetime import datetime

logger = logging.getLogger(__name__)


class BaseParser:
    def parse(self, raw_message: str) -> dict:
        raise NotImplementedError


class GenericSyslogParser(BaseParser):
    PRIORITY_RE = re.compile(r'^<(\d+)>')
    SYSLOG_HEADER_RE = re.compile(
        r'^<?\d+>?(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})?\s+'
        r'(?P<hostname>\S+)?\s+'
        r'(?P<app_name>[^\s:]+)?[:\s]*'
        r'(?P<message>.*)',
        re.DOTALL,
    )

    def parse(self, raw_message: str) -> dict:
        raw = raw_message.strip()
        severity = 'info'
        event_category = 'generic'
        hostname = ''
        host_ip = ''
        app_name = ''
        message = raw

        m = self.SYSLOG_HEADER_RE.match(raw)
        if m:
            hostname = m.group('hostname') or ''
            app_name = m.group('app_name') or ''
            message = m.group('message') or raw

        prio_m = self.PRIORITY_RE.match(raw)
        if prio_m:
            code = int(prio_m.group(1))
            sev_map = {0: 'critical', 1: 'critical', 2: 'critical',
                       3: 'high', 4: 'medium', 5: 'low',
                       6: 'info', 7: 'debug'}
            severity = sev_map.get(code % 8, 'info')

        message_lower = message.lower()
        if any(w in message_lower for w in ('error', 'fail', 'critical', 'alert')):
            severity = 'high'
        elif any(w in message_lower for w in ('warn', 'denied', 'reject')):
            severity = 'medium'

        if app_name:
            event_category = app_name

        return {
            'source_type': 'generic_syslog',
            'severity': severity,
            'event_category': event_category,
            'hostname': hostname,
            'host_ip': host_ip,
            'message': message[:5000],
            'parsed_fields': {'app_name': app_name},
            'tags': ['syslog'],
        }


class GenericJSONParser(BaseParser):
    def parse(self, raw_message: str) -> dict:
        import json
        try:
            data = json.loads(raw_message) if isinstance(raw_message, str) else raw_message
        except json.JSONDecodeError:
            data = {'raw': raw_message}

        return {
            'source_type': data.get('source_type', 'generic_syslog'),
            'severity': data.get('severity', 'info'),
            'event_category': data.get('event_category', 'generic'),
            'hostname': data.get('hostname', ''),
            'host_ip': data.get('host_ip', ''),
            'event_time_dt': data.get('event_time'),
            'message': data.get('message', str(raw_message)),
            'parsed_fields': data.get('parsed_fields', {}),
            'tags': data.get('tags', ['json']),
        }


class HuaweiFirewallParser(BaseParser):
    PATTERN = re.compile(
        r'(?P<datetime>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})?\s*'
        r'(?P<hostname>\S+)?\s*'
        r'(?P<severity>\w+)?\s*'
        r'(?P<message>.*)',
        re.DOTALL,
    )

    def parse(self, raw_message: str) -> dict:
        raw = raw_message.strip()
        m = self.PATTERN.match(raw)
        groups = m.groupdict() if m else {}
        message = groups.get('message', raw)
        severity = groups.get('severity', 'info')
        severity = self._normalize_severity(severity)

        event_category = 'firewall'
        message_lower = message.lower()
        if 'attack' in message_lower:
            event_category = 'intrusion'
            severity = max(severity, 'high', key=lambda x: ['info', 'low', 'medium', 'high', 'critical'].index(x))
        elif 'session' in message_lower and ('created' in message_lower or 'established' in message_lower):
            event_category = 'connection'
        elif 'user' in message_lower and ('login' in message_lower or 'authentication' in message_lower):
            event_category = 'authentication'

        return {
            'source_type': 'firewall_huawei',
            'severity': severity,
            'event_category': event_category,
            'hostname': groups.get('hostname', ''),
            'host_ip': '',
            'message': message[:5000],
            'parsed_fields': {},
            'tags': ['firewall', 'huawei'],
        }

    def _normalize_severity(self, sev: str) -> str:
        mapping = {
            'emergency': 'critical', 'alert': 'critical', 'critical': 'critical',
            'error': 'high', 'err': 'high',
            'warning': 'medium', 'warn': 'medium',
            'notification': 'low', 'notice': 'low',
            'informational': 'info', 'info': 'info',
            'debug': 'debug', 'trace': 'debug',
        }
        return mapping.get(sev.lower(), 'info')


class SnortParser(BaseParser):
    PATTERN = re.compile(
        r'\[\*\*\]\s*\[\d+:\d+:\d+\]\s*(?P<message>[^\[]+?)\s*\[\*\*\]\s*'
        r'\[\s*Classification:\s*(?P<classification>[^\]]+)\s*\]\s*'
        r'\[\s*Priority:\s*(?P<priority>\d+)\s*\]\s*'
        r'(?P<timestamp>[\d/\-:\s]+)?',
        re.DOTALL,
    )

    def parse(self, raw_message: str) -> dict:
        raw = raw_message.strip()
        m = self.PATTERN.match(raw)
        if m:
            message = m.group('message', raw)
            classification = m.group('classification', '')
            priority = int(m.group('priority', 0))
            severity = 'critical' if priority <= 1 else 'high' if priority <= 2 else 'medium'
            event_category = classification.lower().replace(' ', '_') if classification else 'intrusion'
            host_ip = ''
            ip_match = re.search(r'(\d{1,3}\.){3}\d{1,3}', raw)
            if ip_match:
                host_ip = ip_match.group()
        else:
            message = raw
            severity = 'medium'
            event_category = 'intrusion'
            host_ip = ''
            ip_match = re.search(r'(\d{1,3}\.){3}\d{1,3}', raw)
            if ip_match:
                host_ip = ip_match.group()

        return {
            'source_type': 'snort',
            'severity': severity,
            'event_category': event_category,
            'hostname': '',
            'host_ip': host_ip,
            'message': message[:5000],
            'parsed_fields': {},
            'tags': ['ids', 'snort'],
        }


class SuricataParser(BaseParser):
    def parse(self, raw_message: str) -> dict:
        import json
        try:
            data = json.loads(raw_message) if isinstance(raw_message, str) else raw_message
            event_type = data.get('event_type', 'alert')
            alert = data.get('alert', {})
            severity_map = {1: 'critical', 2: 'high', 3: 'medium', 4: 'low'}
            severity = severity_map.get(alert.get('severity', 3), 'medium')
            src_ip = data.get('src_ip', '')
            dest_ip = data.get('dest_ip', '')
            return {
                'source_type': 'suricata',
                'severity': severity,
                'event_category': alert.get('category', event_type),
                'hostname': data.get('hostname', ''),
                'host_ip': src_ip or dest_ip,
                'message': alert.get('signature', raw_message[:5000]),
                'event_time_dt': data.get('timestamp'),
                'parsed_fields': {'src_ip': src_ip, 'dest_ip': dest_ip, 'event_type': event_type},
                'tags': ['ids', 'suricata'],
            }
        except json.JSONDecodeError:
            return GenericSyslogParser().parse(raw_message)


class WindowsADParser(BaseParser):
    EVENT_ID_MAP = {
        4624: ('info', 'logon_success'),
        4625: ('high', 'logon_failure'),
        4634: ('info', 'logoff'),
        4647: ('info', 'logoff_initiated'),
        4648: ('medium', 'logon_explicit'),
        4672: ('medium', 'admin_logon'),
        4720: ('medium', 'user_created'),
        4722: ('info', 'user_enabled'),
        4723: ('medium', 'password_change'),
        4724: ('medium', 'password_reset'),
        4725: ('medium', 'user_disabled'),
        4726: ('high', 'user_deleted'),
        4732: ('info', 'group_member_added'),
        4733: ('info', 'group_member_removed'),
        4740: ('medium', 'account_locked'),
        4767: ('info', 'account_unlocked'),
        4776: ('info', 'credential_validation'),
        4778: ('info', 'session_reconnect'),
        4779: ('info', 'session_disconnect'),
    }

    def parse(self, raw_message: str) -> dict:
        event_id = None
        id_match = re.search(r'EventID[:\s]*(\d+)', raw_message, re.IGNORECASE)
        if id_match:
            event_id = int(id_match.group(1))

        if event_id and event_id in self.EVENT_ID_MAP:
            severity, category = self.EVENT_ID_MAP[event_id]
        else:
            severity = 'info'
            category = 'windows_event'
            if event_id:
                if 1000 <= event_id < 2000:
                    category = 'system_event'
                elif event_id >= 5000:
                    category = 'security_event'

        user_match = re.search(r'Account\s*(Name|For)[:\s]*(\S+)', raw_message)
        account_name = user_match.group(2) if user_match else ''

        return {
            'source_type': 'windows_ad',
            'severity': severity,
            'event_category': category,
            'hostname': '',
            'host_ip': '',
            'message': raw_message[:5000],
            'parsed_fields': {'event_id': event_id, 'account_name': account_name},
            'tags': ['windows', 'active_directory'],
        }


class FortigateParser(BaseParser):
    PATTERN = re.compile(
        r'date=(?P<date>\S+)\s+time=(?P<time>\S+)\s+'
        r'devname=(?P<devname>\S+)\s+'
        r'type=(?P<type>\S+)\s+'
        r'subtype=(?P<subtype>\S+)\s+'
        r'level=(?P<level>\S+)\s+'
        r'vd=(?P<vd>\S+)\s+'
        r'(?P<rest>.*)',
        re.DOTALL,
    )

    def parse(self, raw_message: str) -> dict:
        raw = raw_message.strip()
        m = self.PATTERN.match(raw)
        if m:
            level = m.group('level', 'information')
            sev_map = {'emergency': 'critical', 'alert': 'critical', 'critical': 'critical',
                       'error': 'high', 'warning': 'medium',
                       'notification': 'low', 'information': 'info', 'debug': 'debug'}
            severity = sev_map.get(level.lower(), 'info')
            event_type = m.group('type', 'traffic')
            subtype = m.group('subtype', '')
            event_category = f'{event_type}_{subtype}' if subtype else event_type
            hostname = m.group('devname', '')
        else:
            severity = 'info'
            event_category = 'firewall'
            hostname = ''

        return {
            'source_type': 'fortigate',
            'severity': severity,
            'event_category': event_category,
            'hostname': hostname,
            'host_ip': '',
            'message': raw[:5000],
            'parsed_fields': {},
            'tags': ['firewall', 'fortinet'],
        }


class PaloAltoParser(BaseParser):
    def parse(self, raw_message: str) -> dict:
        raw = raw_message.strip()
        severity = 'info'
        event_category = 'traffic'

        if ',THREAT,' in raw:
            event_category = 'threat'
            severity = 'high'
        elif ',CONFIG,' in raw:
            event_category = 'configuration'
        elif ',SYSTEM,' in raw:
            event_category = 'system'
        elif ',TRAFFIC,' in raw:
            event_category = 'traffic'

        if 'critical' in raw.lower() or 'alert' in raw.lower():
            severity = 'critical'
        elif 'high' in raw.lower():
            severity = 'high'
        elif 'medium' in raw.lower() or 'warn' in raw.lower():
            severity = 'medium'
        elif 'low' in raw.lower():
            severity = 'low'

        return {
            'source_type': 'paloalto',
            'severity': severity,
            'event_category': event_category,
            'hostname': '',
            'host_ip': '',
            'message': raw[:5000],
            'parsed_fields': {},
            'tags': ['firewall', 'paloalto'],
        }


class CiscoFirewallParser(BaseParser):
    ASA_MSG_RE = re.compile(
        r'%\w+-(?P<severity_level>\d)-(?P<msg_id>\d+):\s*(?P<message>.*)',
        re.DOTALL,
    )

    def parse(self, raw_message: str) -> dict:
        raw = raw_message.strip()
        m = self.ASA_MSG_RE.match(raw)
        if m:
            sev_num = int(m.group('severity_level', 6))
            sev_map = {0: 'critical', 1: 'critical', 2: 'critical',
                       3: 'high', 4: 'medium', 5: 'medium',
                       6: 'info', 7: 'debug'}
            severity = sev_map.get(sev_num, 'info')
            message = m.group('message', raw)
        else:
            severity = 'info'
            message = raw

        event_category = 'firewall'
        message_lower = message.lower()
        if 'denied' in message_lower or 'deny' in message_lower:
            event_category = 'access_denied'
            if severity == 'info':
                severity = 'medium'
        elif 'attack' in message_lower or 'intrusion' in message_lower:
            event_category = 'intrusion'
            severity = 'high'

        return {
            'source_type': 'firewall_cisco',
            'severity': severity,
            'event_category': event_category,
            'hostname': '',
            'host_ip': '',
            'message': message[:5000],
            'parsed_fields': {},
            'tags': ['firewall', 'cisco'],
        }


_PARSER_REGISTRY = {
    'generic_syslog': GenericSyslogParser,
    'firewall_huawei': HuaweiFirewallParser,
    'snort': SnortParser,
    'suricata': SuricataParser,
    'windows_ad': WindowsADParser,
    'windows_dhcp': WindowsADParser,
    'windows_dns': WindowsADParser,
    'samba': GenericSyslogParser,
    'switch': GenericSyslogParser,
    'router': GenericSyslogParser,
    'modem': GenericSyslogParser,
    'agent_filelog': GenericJSONParser,
    'firewall_cisco': CiscoFirewallParser,
    'fortigate': FortigateParser,
    'paloalto': PaloAltoParser,
}


def get_parser(source_type: str) -> BaseParser:
    parser_cls = _PARSER_REGISTRY.get(source_type)
    if parser_cls is None:
        logger.warning(f'No parser found for source_type={source_type}, fallback to GenericSyslogParser')
        parser_cls = GenericSyslogParser
    return parser_cls()
