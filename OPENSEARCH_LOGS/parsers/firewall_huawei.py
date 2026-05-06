import re
from .base import BaseParser

class HuaweiFirewallParser(BaseParser):
    source_type = 'firewall_huawei'

    _RULE_RE = re.compile(r'(?:rule|policy|acl)[=:\s]+(\S+)', re.IGNORECASE)
    _ACTION_RE = re.compile(r'(?:action|result)[=:\s]+(\w+)', re.IGNORECASE)
    _IFACE_RE = re.compile(r'(?:interface|if)[=:\s]+([\w/]+)', re.IGNORECASE)
    _ZONE_RE = re.compile(r'(?:zone|src-zone|dst-zone)[=:\s]+(\S+)', re.IGNORECASE)
    _NAT_RE = re.compile(r'(?:NAT|nat)[=:\s]+(\S+)', re.IGNORECASE)
    _USER_RE = re.compile(r'(?:user|account|username)[=:\s]+([\w.@-]+)', re.IGNORECASE)
    _SRC_IP_RE = re.compile(r'(?:src[_-]?ip|source[_-]?ip|src)[=:\s]+([\d.]+)', re.IGNORECASE)
    _DST_IP_RE = re.compile(r'(?:dst[_-]?ip|dest[_-]?ip|destination[_-]?ip|dst|dest)[=:\s]+([\d.]+)', re.IGNORECASE)
    _SRC_PORT_RE = re.compile(r'(?:src[_-]?port|source[_-]?port|spt|sport)[=:\s]+(\d+)', re.IGNORECASE)
    _DST_PORT_RE = re.compile(r'(?:dst[_-]?port|dest[_-]?port|dpt|dport)[=:\s]+(\d+)', re.IGNORECASE)
    _PROTO_RE = re.compile(r'(?:proto(?:col)?|protocol)[=:\s]+(\w+)', re.IGNORECASE)
    _APP_RE = re.compile(r'(?:app(?:lication)?|service)[=:\s]+([\w.-]+)', re.IGNORECASE)
    _BYTES_RE = re.compile(r'(?:bytes?|len(?:gth)?|size)[=:\s]+(\d+)', re.IGNORECASE)
    _SESSION_RE = re.compile(r'(?:session|conn)[=:\s]+(\S+)', re.IGNORECASE)

    def _extract_fields(self, raw: str) -> dict:
        fields = {}
        m = self._SRC_IP_RE.search(raw)
        if m: fields['src_ip'] = m.group(1)
        m = self._DST_IP_RE.search(raw)
        if m: fields['dst_ip'] = m.group(1)
        m = self._SRC_PORT_RE.search(raw)
        if m: fields['src_port'] = int(m.group(1))
        m = self._DST_PORT_RE.search(raw)
        if m: fields['dst_port'] = int(m.group(1))
        m = self._PROTO_RE.search(raw)
        if m: fields['protocol'] = m.group(1).upper()
        m = self._ACTION_RE.search(raw)
        if m:
            action = m.group(1).lower()
            fields['action'] = 'permit' if action in ('permit', 'allow', 'pass', 'accept') else 'deny' if action in ('deny', 'drop', 'block', 'reject') else action
        m = self._RULE_RE.search(raw)
        if m: fields['rule'] = m.group(1)
        m = self._IFACE_RE.search(raw)
        if m: fields['interface'] = m.group(1)
        m = self._ZONE_RE.search(raw)
        if m: fields['zone'] = m.group(1)
        m = self._NAT_RE.search(raw)
        if m: fields['nat'] = m.group(1)
        m = self._USER_RE.search(raw)
        if m: fields['user'] = m.group(1)
        m = self._APP_RE.search(raw)
        if m: fields['application'] = m.group(1)
        m = self._BYTES_RE.search(raw)
        if m: fields['bytes'] = int(m.group(1))
        m = self._SESSION_RE.search(raw)
        if m: fields['session_id'] = m.group(1)
        fields['host_ip'] = fields.get('src_ip')
        return fields

    def _guess_category(self, parsed: dict) -> str:
        action = parsed.get('action', '').lower()
        if action == 'deny': return 'traffic_blocked'
        if action == 'permit': return 'traffic_allowed'
        app = parsed.get('application', '').lower()
        if app in ('ips', 'ids', 'av', 'antivirus', 'threat'): return 'threat_prevention'
        if parsed.get('nat'): return 'nat'
        if parsed.get('user'): return 'authentication'
        return 'traffic'

    def _build_tags(self, parsed: dict) -> list:
        tags = ['firewall', 'huawei']
        action = parsed.get('action', '').lower()
        if action == 'deny': tags.extend(['deny', 'blocked'])
        elif action == 'permit': tags.append('permit')
        if parsed.get('nat'): tags.append('nat')
        if parsed.get('protocol'): tags.append(parsed['protocol'].lower())
        if parsed.get('zone'): tags.append(f"zone:{parsed['zone']}")
        return tags
