import json
from .base import BaseParser

class SuricataParser(BaseParser):
    source_type = 'suricata'

    def _extract_fields(self, raw: str) -> dict:
        fields = {}
        try:
            data = json.loads(raw)
            event_type = data.get('event_type', 'alert')
            fields['event_type'] = event_type
            fields['src_ip'] = data.get('src_ip') or data.get('source_ip')
            fields['dst_ip'] = data.get('dest_ip') or data.get('dst_ip')
            fields['src_port'] = data.get('src_port') or data.get('source_port')
            fields['dst_port'] = data.get('dest_port') or data.get('dst_port')
            if fields.get('src_port'): fields['src_port'] = int(fields['src_port'])
            if fields.get('dst_port'): fields['dst_port'] = int(fields['dst_port'])
            fields['protocol'] = (data.get('proto') or data.get('protocol') or '').upper()
            fields['host_ip'] = fields.get('src_ip')

            if event_type == 'alert':
                alert = data.get('alert', {})
                fields['signature'] = alert.get('signature') or alert.get('msg', '')
                fields['alert_id'] = alert.get('signature_id') or alert.get('sid')
                fields['priority'] = alert.get('severity') or alert.get('priority')
                fields['classtype'] = alert.get('category') or alert.get('classtype')
                fields['action'] = alert.get('action', '')
                fields['severity_value'] = alert.get('severity')
            elif event_type == 'flow':
                fields['flow_id'] = data.get('flow_id')
                fields['flow_start'] = data.get('flow', {}).get('start')
                fields['bytes_to_client'] = data.get('flow', {}).get('bytes_toclient')
                fields['bytes_to_server'] = data.get('flow', {}).get('bytes_toserver')
            elif event_type == 'dns':
                dns = data.get('dns', {})
                fields['query'] = dns.get('query', '')
                fields['query_type'] = dns.get('type', '')
                fields['rcode'] = dns.get('rcode', '')
                fields['answers'] = dns.get('answers', [])
            elif event_type == 'http':
                http = data.get('http', {})
                fields['http_method'] = http.get('http_method', '')
                fields['http_url'] = http.get('url', '')
                fields['http_status'] = http.get('status')
                fields['http_hostname'] = http.get('hostname', '')
                fields['http_content_type'] = http.get('http_content_type', '')

            fields['tx_id'] = data.get('tx_id')
            fields['flow_id'] = data.get('flow_id')
            fields['pcap_cnt'] = data.get('pcap_cnt')
            return fields
        except (json.JSONDecodeError, ValueError):
            pass
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
        event_type = parsed.get('event_type', '')
        if event_type == 'alert':
            sig = (parsed.get('signature') or '').lower()
            ct = (parsed.get('classtype') or '').lower()
            if 'malware' in sig or 'trojan' in sig: return 'malware'
            if 'sql' in sig or 'xss' in sig or 'injection' in sig: return 'exploit'
            if 'scan' in sig or 'scan' in ct: return 'reconnaissance'
            return 'ids_alert'
        elif event_type == 'dns':
            return 'dns_query'
        elif event_type == 'http':
            return 'http_traffic'
        elif event_type == 'flow':
            return 'flow'
        return 'network_event'

    def _build_tags(self, parsed: dict) -> list:
        tags = ['suricata', 'eve', parsed.get('event_type', 'unknown')]
        if parsed.get('protocol'): tags.append(parsed['protocol'].lower())
        if parsed.get('priority'): tags.append(f"priority:{parsed['priority']}")
        if parsed.get('action'): tags.append(parsed['action'].lower())
        return tags
