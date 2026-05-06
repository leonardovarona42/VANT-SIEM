import json
import re
from .base import BaseParser

class WindowsDHCPParser(BaseParser):
    source_type = 'windows_dhcp'

    _EVENT_ID_RE = re.compile(r'(?:EventID|Event ID|ID)[=:\s]+(\d+)', re.IGNORECASE)
    _IP_RE = re.compile(r'(?:IP|IP Address|Assigned IP|Client IP)[=:\s]+([\d.]+)', re.IGNORECASE)
    _MAC_RE = re.compile(r'(?:MAC|MAC Address|Client MAC)[=:\s]+([\w:-]{12,17})', re.IGNORECASE)
    _HOSTNAME_RE = re.compile(r'(?:Hostname|Client Name|Computer Name)[=:\s]+([^\s,;]+)', re.IGNORECASE)
    _LEASE_RE = re.compile(r'(?:Lease|Lease Expiry)[=:\s]+(.+?)(?:\n|,|$)', re.IGNORECASE)

    EVENT_CATEGORIES = {
        10: 'dhcp_log_on', 11: 'dhcp_log_off', 12: 'dhcp_log_off',
        13: 'dhcp_log_off', 14: 'dhcp_log_off', 15: 'dhcp_log_off',
        16: 'dhcp_log_on', 17: 'dhcp_log_on',
        1001: 'lease_assigned', 1002: 'lease_renewed', 1003: 'lease_released',
        1004: 'lease_expired', 1005: 'lease_nak', 1006: 'lease_decline',
        1010: 'scope_full', 1011: 'scope_almost_full',
        1020: 'audit_log_on', 1021: 'audit_log_off',
        1022: 'dhcp_service_start', 1023: 'dhcp_service_stop',
    }

    def _extract_fields(self, raw: str) -> dict:
        fields = {}
        try:
            data = json.loads(raw)
            fields['event_id'] = data.get('EventID') or data.get('event_id') or data.get('Id')
            fields['client_ip'] = data.get('ClientIP') or data.get('client_ip') or data.get('IPAddress')
            fields['mac_address'] = data.get('MACAddress') or data.get('mac_address') or data.get('MAC')
            fields['hostname'] = data.get('Hostname') or data.get('hostname') or data.get('ClientName')
            fields['lease_duration'] = data.get('LeaseDuration') or data.get('lease_duration')
            fields['scope_id'] = data.get('ScopeId') or data.get('scope_id')
            fields['server_ip'] = data.get('ServerIP') or data.get('server_ip')
            fields['host_ip'] = fields.get('client_ip') or fields.get('server_ip')
            return fields
        except (json.JSONDecodeError, ValueError):
            pass
        m = self._EVENT_ID_RE.search(raw)
        if m: fields['event_id'] = int(m.group(1))
        m = self._IP_RE.search(raw)
        if m: fields['client_ip'] = m.group(1)
        m = self._MAC_RE.search(raw)
        if m: fields['mac_address'] = m.group(1)
        m = self._HOSTNAME_RE.search(raw)
        if m: fields['hostname'] = m.group(1)
        m = self._LEASE_RE.search(raw)
        if m: fields['lease_info'] = m.group(1).strip()
        fields['host_ip'] = fields.get('client_ip') or self._extract_ip(raw)
        return fields

    def _guess_category(self, parsed: dict) -> str:
        event_id = parsed.get('event_id')
        if event_id:
            return self.EVENT_CATEGORIES.get(int(event_id), 'dhcp')
        return 'dhcp'

    def _build_tags(self, parsed: dict) -> list:
        tags = ['windows', 'dhcp', 'network']
        event_id = parsed.get('event_id')
        if event_id: tags.append(f"event_id:{event_id}")
        if parsed.get('mac_address'): tags.append(f"mac:{parsed['mac_address']}")
        if parsed.get('hostname'): tags.append(f"host:{parsed['hostname']}")
        return tags
