import json
from .base import BaseParser

class SnortParser(BaseParser):
    source_type = 'snort'

    _SID_RE = '[=:]\s*(\d+)'
    _CLASS_RE = r'classtype[=:]\s*([\w-]+)'
    _PRIO_RE = r'priority[=:]\s*(\d+)'
    _PROTO_RE = r'(?:TCP|UDP|ICMP|IP)\s'

    def _extract_fields(self, raw: str) -> dict:
        fields = {}
        try:
            data = json.loads(raw)
            fields.update(data)
            fields['src_ip'] = data.get('src_ip') or data.get('ip_src') or data.get('source_ip')
            fields['dst_ip'] = data.get('dst_ip') or data.get('ip_dst') or data.get('dest_ip')
            fields['src_port'] = data.get('src_port') or data.get('sport')
            fields['dst_port'] = data.get('dst_port') or data.get('dport')
            if fields.get('src_port'): fields['src_port'] = int(fields['src_port'])
            if fields.get('dst_port'): fields['dst_port'] = int(fields['dst_port'])
            fields['protocol'] = (data.get('protocol') or data.get('proto') or '').upper()
            fields['signature'] = data.get('signature') or data.get('msg') or data.get('message', '')
            fields['alert_id'] = data.get('alert_id') or data.get('sid') or data.get('gid')
            fields['priority'] = data.get('priority') or data.get('pri')
            fields['classtype'] = data.get('classtype') or data.get('class')
            fields['payload'] = data.get('payload') or data.get('payload_base64')
            fields['host_ip'] = fields.get('src_ip')
            return fields
        except (json.JSONDecodeError, ValueError):
            pass
        parts = raw.strip().split('|') if '|' in raw else raw.strip().split('\t')
        if len(parts) >= 6:
            fields['timestamp'] = parts[0].strip()
            fields['src_ip'] = parts[1].strip()
            fields['dst_ip'] = parts[2].strip()
            fields['src_port'] = int(parts[3].strip()) if parts[3].strip().isdigit() else None
            fields['dst_port'] = int(parts[4].strip()) if parts[4].strip().isdigit() else None
            fields['signature'] = parts[5].strip()
            fields['host_ip'] = fields.get('src_ip')
            return fields
        fields['message'] = raw
        fields['host_ip'] = self._extract_ip(raw)
        return fields

    def _normalize_severity(self, sev) -> str:
        if isinstance(sev, int):
            if sev <= 1: return 'critical'
            if sev == 2: return 'high'
            if sev == 3: return 'medium'
            return 'low'
        return super()._normalize_severity(sev)

    def _guess_category(self, parsed: dict) -> str:
        ct = (parsed.get('classtype') or '').lower()
        if 'attempted' in ct: return 'attack_attempt'
        if 'successful' in ct: return 'successful_attack'
        if 'policy' in ct: return 'policy_violation'
        if 'bad' in ct or 'malware' in ct: return 'malware'
        if 'scan' in ct: return 'reconnaissance'
        sig = (parsed.get('signature') or '').lower()
        if any(w in sig for w in ('malware', 'trojan', 'virus', 'backdoor')): return 'malware'
        if any(w in sig for w in ('scan', 'sweep', 'probe')): return 'reconnaissance'
        if any(w in sig for w in ('sql', 'xss', 'injection', 'exploit')): return 'exploit'
        return 'ids_alert'

    def _build_tags(self, parsed: dict) -> list:
        tags = ['snort', 'ids', 'alert']
        ct = parsed.get('classtype', '')
        if ct: tags.append(f"class:{ct}")
        if parsed.get('protocol'): tags.append(parsed['protocol'].lower())
        if parsed.get('priority'): tags.append(f"priority:{parsed['priority']}")
        return tags
