import re
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network

logger = logging.getLogger(__name__)

IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
PORT_PATTERN = re.compile(r'(?:port|dpt|spt|srcport|dstport|dport|sport)[=:\s]+(\d+)', re.IGNORECASE)
PROTOCOL_PATTERN = re.compile(r'(?:proto(?:col)?|proto)[=:\s]+(\w+)', re.IGNORECASE)

SEVERITY_MAP = {
    '0': 'critical', '1': 'critical', '2': 'critical', 'emerg': 'critical', 'emergency': 'critical', 'critical': 'critical', 'crit': 'critical', 'fatal': 'critical',
    '3': 'high', 'alert': 'high', 'high': 'high', 'error': 'high', 'err': 'high',
    '4': 'medium', 'warning': 'medium', 'warn': 'medium', 'medium': 'medium',
    '5': 'low', 'notice': 'low', 'low': 'low',
    '6': 'info', 'informational': 'info', 'info': 'info', 'information': 'info',
    '7': 'debug', 'debug': 'debug',
}

class BaseParser(ABC):
    source_type = 'unknown'

    def parse(self, raw_message: str) -> dict:
        result = {
            'source_type': self.source_type,
            'severity': 'info',
            'event_category': 'unknown',
            'host_ip': None,
            'parsed_fields': {},
            'tags': [],
        }
        try:
            normalized = self._normalize(raw_message)
            parsed = self._extract_fields(normalized)
            result.update(parsed)
            result['severity'] = self._normalize_severity(parsed.get('severity', 'info'))
            result['event_category'] = parsed.get('event_category', self._guess_category(parsed))
            result['host_ip'] = parsed.get('host_ip') or self._extract_ip(normalized)
            result['tags'] = self._build_tags(parsed)
            result['parsed_fields'] = self._normalize_fields(parsed)
        except Exception as e:
            logger.error(f'Parser error [{self.source_type}]: {e}')
            result['parsed_fields'] = {'parse_error': str(e)}
            result['severity'] = 'warning'
            result['event_category'] = 'parse_error'
        return result

    @abstractmethod
    def _extract_fields(self, raw: str) -> dict:
        pass

    def _normalize(self, raw: str) -> str:
        return raw.strip()

    def _normalize_severity(self, sev) -> str:
        if isinstance(sev, int):
            return SEVERITY_MAP.get(str(sev), 'info')
        return SEVERITY_MAP.get(str(sev).lower(), 'info')

    def _extract_ip(self, text: str) -> str:
        ips = IP_PATTERN.findall(text)
        return ips[0] if ips else None

    def _extract_ips(self, text: str) -> list:
        return list(set(IP_PATTERN.findall(text)))

    def _extract_port(self, text: str) -> str:
        m = PORT_PATTERN.search(text)
        return m.group(1) if m else None

    def _extract_protocol(self, text: str) -> str:
        m = PROTOCOL_PATTERN.search(text)
        return m.group(1).upper() if m else None

    def _guess_category(self, parsed: dict) -> str:
        return 'unknown'

    def _build_tags(self, parsed: dict) -> list:
        return [self.source_type]

    def _normalize_fields(self, fields: dict) -> dict:
        clean = {}
        for k, v in fields.items():
            if v is not None and v != '' and k != 'source_type':
                clean[k] = v
        return clean
