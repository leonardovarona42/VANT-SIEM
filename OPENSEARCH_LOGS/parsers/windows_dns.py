import json
import re
from .base import BaseParser

class WindowsDNSParser(BaseParser):
    source_type = 'windows_dns'

    _EVENT_ID_RE = re.compile(r'(?:EventID|Event ID|ID)[=:\s]+(\d+)', re.IGNORECASE)
    _QUERY_RE = re.compile(r'(?:Query|Query Name|Domain)[=:\s]+([^\s,;]+)', re.IGNORECASE)
    _QTYPE_RE = re.compile(r'(?:Query Type|Type|Record Type)[=:\s]+(\w+)', re.IGNORECASE)
    _RESPONSE_RE = re.compile(r'(?:Response|Answer|Resolved IP)[=:\s]+([\d.]+)', re.IGNORECASE)
    _CLIENT_RE = re.compile(r'(?:Client|Client IP|Source)[=:\s]+([\d.]+)', re.IGNORECASE)
    _ZONE_RE = re.compile(r'(?:Zone|Zone Name)[=:\s]+([^\s,;]+)', re.IGNORECASE)

    EVENT_CATEGORIES = {
        256: 'dns_query', 257: 'dns_response', 258: 'dns_update',
        260: 'dns_notify', 262: 'dns_zone_transfer', 264: 'dns_dynamic_update',
        272: 'dns_record_created', 273: 'dns_record_deleted',
        394: 'dns_server_start', 395: 'dns_server_stop',
        401: 'dns_plugin_load', 403: 'dns_plugin_error',
        4014: 'dns_secure_operation', 4015: 'dns_secure_error',
        4000: 'dns_packet',
    }

    def _extract_fields(self, raw: str) -> dict:
        fields = {}
        try:
            data = json.loads(raw)
            fields['event_id'] = data.get('EventID') or data.get('event_id') or data.get('Id')
            fields['query'] = data.get('Query') or data.get('query') or data.get('QueryName')
            fields['query_type'] = data.get('QueryType') or data.get('query_type') or data.get('Type')
            fields['response_ip'] = data.get('Response') or data.get('response_ip') or data.get('Answer')
            fields['client_ip'] = data.get('ClientIP') or data.get('client_ip') or data.get('Source')
            fields['zone'] = data.get('Zone') or data.get('zone') or data.get('ZoneName')
            fields['rcode'] = data.get('Rcode') or data.get('rcode') or data.get('response_code')
            fields['server_ip'] = data.get('ServerIP') or data.get('server_ip')
            fields['host_ip'] = fields.get('client_ip')
            return fields
        except (json.JSONDecodeError, ValueError):
            pass
        m = self._EVENT_ID_RE.search(raw)
        if m: fields['event_id'] = int(m.group(1))
        m = self._QUERY_RE.search(raw)
        if m: fields['query'] = m.group(1)
        m = self._QTYPE_RE.search(raw)
        if m: fields['query_type'] = m.group(1)
        m = self._RESPONSE_RE.search(raw)
        if m: fields['response_ip'] = m.group(1)
        m = self._CLIENT_RE.search(raw)
        if m: fields['client_ip'] = m.group(1)
        m = self._ZONE_RE.search(raw)
        if m: fields['zone'] = m.group(1)
        fields['host_ip'] = fields.get('client_ip') or self._extract_ip(raw)
        return fields

    def _guess_category(self, parsed: dict) -> str:
        event_id = parsed.get('event_id')
        if event_id:
            return self.EVENT_CATEGORIES.get(int(event_id), 'dns')
        return 'dns'

    def _build_tags(self, parsed: dict) -> list:
        tags = ['windows', 'dns', 'resolution']
        event_id = parsed.get('event_id')
        if event_id: tags.append(f"event_id:{event_id}")
        if parsed.get('query'): tags.append(f"query:{parsed['query']}")
        if parsed.get('query_type'): tags.append(parsed['query_type'].lower())
        if parsed.get('rcode'): tags.append(f"rcode:{parsed['rcode']}")
        return tags
