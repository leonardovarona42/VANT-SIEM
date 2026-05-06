import re
from datetime import datetime
from .base import BaseParser

class GenericSyslogParser(BaseParser):
    source_type = 'generic_syslog'

    _SYSLOG_RE = re.compile(
        r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>[\w.-]+)\s+'
        r'(?P<process>[\w/.-]+?)(?:\[(?P<pid>\d+)\])?'
        r':\s*(?P<message>.+)$'
    )
    _SYSLOG_RE2 = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+'
        r'(?P<host>[\w.-]+)\s+'
        r'(?P<process>[\w/.-]+?)(?:\[(?P<pid>\d+)\])?'
        r':\s*(?P<message>.+)$'
    )

    FACILITY_SEVERITY = {
        0: 'critical', 1: 'critical', 2: 'critical', 3: 'high',
        4: 'medium', 5: 'low', 6: 'info', 7: 'debug',
    }

    def _extract_fields(self, raw: str) -> dict:
        fields = {}
        m = self._SYSLOG_RE.search(raw)
        if not m:
            m = self._SYSLOG_RE2.search(raw)
        if m:
            fields['timestamp_str'] = m.group('timestamp')
            fields['hostname'] = m.group('host')
            fields['process'] = m.group('process')
            fields['pid'] = m.group('pid')
            fields['message'] = m.group('message')
            fields['host_ip'] = self._extract_ip(raw)
            fields['severity'] = self._detect_severity(m.group('message'))
            fields['event_category'] = self._categorize(m.group('message'), m.group('process'))
            return fields
        fields['message'] = raw
        fields['host_ip'] = self._extract_ip(raw)
        fields['hostname'] = self._extract_hostname(raw)
        fields['severity'] = self._detect_severity(raw)
        fields['event_category'] = self._categorize(raw, '')
        return fields

    def _detect_severity(self, text: str) -> str:
        text_lower = text.lower()
        if any(w in text_lower for w in ('emergency', 'emerg', 'panic')): return 'critical'
        if any(w in text_lower for w in ('critical', 'crit', 'fatal', 'alert')): return 'critical'
        if any(w in text_lower for w in ('error', 'err', 'fail', 'denied', 'refused')): return 'high'
        if any(w in text_lower for w in ('warning', 'warn')): return 'medium'
        if any(w in text_lower for w in ('notice', 'info', 'information')): return 'info'
        if any(w in text_lower for w in ('debug')): return 'debug'
        return 'info'

    def _categorize(self, text: str, process: str) -> str:
        text_lower = text.lower()
        process_lower = (process or '').lower()
        if any(w in text_lower for w in ('login', 'logon', 'auth', 'password', 'session opened', 'session closed')):
            return 'authentication'
        if any(w in text_lower for w in ('firewall', 'iptables', 'ufw', 'fw', 'deny', 'drop', 'blocked')):
            return 'firewall'
        if any(w in text_lower for w in ('cron', 'schedule', 'timer')):
            return 'scheduler'
        if any(w in text_lower for w in ('kernel', 'panic', 'oom', 'segfault')):
            return 'kernel'
        if any(w in text_lower for w in ('disk', 'mount', 'filesystem', 'storage', 'io error')):
            return 'storage'
        if 'sudo' in process_lower or 'su ' in text_lower:
            return 'privilege_escalation'
        if 'ssh' in process_lower or 'sshd' in process_lower:
            return 'ssh'
        if any(w in text_lower for w in ('network', 'interface', 'link', 'dhcp')):
            return 'network'
        return 'system'

    def _extract_hostname(self, text: str) -> str:
        parts = text.split()
        if len(parts) >= 3:
            return parts[2]
        return None

    def _build_tags(self, parsed: dict) -> list:
        tags = ['syslog', 'generic']
        if parsed.get('hostname'): tags.append(f"host:{parsed['hostname']}")
        if parsed.get('process'): tags.append(f"process:{parsed['process']}")
        if parsed.get('event_category'): tags.append(parsed['event_category'])
        return tags
