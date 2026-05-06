import json
import re
from .base import BaseParser

class WindowsADParser(BaseParser):
    source_type = 'windows_ad'

    _EVENT_ID_RE = re.compile(r'(?:EventID|Event ID)[=:\s]+(\d+)', re.IGNORECASE)
    _ACCOUNT_RE = re.compile(r'(?:Account\s*Name|TargetUserName|AccountName)[=:\s]+([^\s,;]+)', re.IGNORECASE)
    _LOGON_TYPE_RE = re.compile(r'(?:Logon\s*Type|LogonType)[=:\s]+(\d+)', re.IGNORECASE)
    _WORKSTATION_RE = re.compile(r'(?:Workstation\s*Name|WorkstationName)[=:\s]+([^\s,;]+)', re.IGNORECASE)
    _REASON_RE = re.compile(r'(?:Failure\s*Reason|FailureReason)[=:\s]+(.+?)(?:\n|,|$)', re.IGNORECASE)
    _DOMAIN_RE = re.compile(r'(?:Domain|TargetDomainName)[=:\s]+([^\s,;]+)', re.IGNORECASE)

    EVENT_CATEGORIES = {
        4624: 'logon_success', 4625: 'logon_failure', 4634: 'logoff',
        4648: 'logon_explicit', 4672: 'special_logon', 4720: 'user_created',
        4722: 'user_enabled', 4723: 'password_change', 4724: 'password_reset',
        4726: 'user_deleted', 4728: 'group_member_added', 4729: 'group_member_removed',
        4732: 'local_group_member_added', 4733: 'local_group_member_removed',
        4740: 'account_locked', 4767: 'account_unlocked', 4768: 'kerberos_tgt_request',
        4769: 'kerberos_service_ticket', 4771: 'kerberos_auth_failed',
        4776: 'ntlm_auth', 4798: 'local_group_enumeration', 5136: 'directory_object_changed',
        5137: 'directory_object_created', 5141: 'directory_object_deleted',
        5145: 'share_access', 4932: 'replication_sync',
    }

    def _extract_fields(self, raw: str) -> dict:
        fields = {}
        try:
            data = json.loads(raw)
            fields['event_id'] = data.get('EventID') or data.get('event_id') or data.get('Id')
            fields['account_name'] = data.get('AccountName') or data.get('account_name') or data.get('TargetUserName')
            fields['logon_type'] = data.get('LogonType') or data.get('logon_type')
            fields['workstation'] = data.get('Workstation') or data.get('workstation') or data.get('WorkstationName')
            fields['failure_reason'] = data.get('FailureReason') or data.get('failure_reason')
            fields['domain'] = data.get('Domain') or data.get('domain') or data.get('TargetDomainName')
            fields['src_ip'] = data.get('IpAddress') or data.get('ip_address') or data.get('source_ip')
            fields['host_ip'] = fields.get('src_ip')
            fields['subject_user'] = data.get('SubjectUserName') or data.get('Subject_User_Name')
            fields['process'] = data.get('ProcessName') or data.get('process')
            return fields
        except (json.JSONDecodeError, ValueError):
            pass
        m = self._EVENT_ID_RE.search(raw)
        if m: fields['event_id'] = int(m.group(1))
        m = self._ACCOUNT_RE.search(raw)
        if m: fields['account_name'] = m.group(1)
        m = self._LOGON_TYPE_RE.search(raw)
        if m: fields['logon_type'] = int(m.group(1))
        m = self._WORKSTATION_RE.search(raw)
        if m: fields['workstation'] = m.group(1)
        m = self._REASON_RE.search(raw)
        if m: fields['failure_reason'] = m.group(1).strip()
        m = self._DOMAIN_RE.search(raw)
        if m: fields['domain'] = m.group(1)
        fields['host_ip'] = self._extract_ip(raw)
        return fields

    def _normalize_severity(self, sev) -> str:
        event_id = getattr(self, '_last_event_id', None)
        if event_id:
            if event_id in (4625, 4740, 4771, 4648): return 'high'
            if event_id in (4720, 4722, 4724, 4726): return 'medium'
            return 'info'
        return super()._normalize_severity(sev)

    def _extract_fields(self, raw: str) -> dict:
        fields = super()._extract_fields(raw) if hasattr(super(), '_extract_fields') else {}
        try:
            data = json.loads(raw)
            fields.update({k: v for k, v in data.items() if k not in fields})
            fields['event_id'] = data.get('EventID') or data.get('event_id') or data.get('Id') or fields.get('event_id')
            fields['account_name'] = data.get('AccountName') or data.get('TargetUserName') or fields.get('account_name')
            fields['logon_type'] = data.get('LogonType') or data.get('logon_type') or fields.get('logon_type')
            fields['workstation'] = data.get('Workstation') or data.get('WorkstationName') or fields.get('workstation')
            fields['failure_reason'] = data.get('FailureReason') or fields.get('failure_reason')
            fields['domain'] = data.get('Domain') or data.get('TargetDomainName') or fields.get('domain')
            fields['src_ip'] = data.get('IpAddress') or data.get('source_ip') or fields.get('src_ip')
            fields['host_ip'] = fields.get('src_ip')
            fields['subject_user'] = data.get('SubjectUserName') or data.get('Subject_User_Name')
            fields['process'] = data.get('ProcessName')
            event_id = fields.get('event_id')
            if event_id:
                self._last_event_id = int(event_id)
            return fields
        except (json.JSONDecodeError, ValueError):
            pass
        m = self._EVENT_ID_RE.search(raw)
        if m:
            event_id = int(m.group(1))
            fields['event_id'] = event_id
            self._last_event_id = event_id
        m = self._ACCOUNT_RE.search(raw)
        if m: fields['account_name'] = m.group(1)
        m = self._LOGON_TYPE_RE.search(raw)
        if m: fields['logon_type'] = int(m.group(1))
        m = self._WORKSTATION_RE.search(raw)
        if m: fields['workstation'] = m.group(1)
        m = self._REASON_RE.search(raw)
        if m: fields['failure_reason'] = m.group(1).strip()
        m = self._DOMAIN_RE.search(raw)
        if m: fields['domain'] = m.group(1)
        fields['host_ip'] = self._extract_ip(raw)
        return fields

    def _guess_category(self, parsed: dict) -> str:
        event_id = parsed.get('event_id')
        if event_id:
            return self.EVENT_CATEGORIES.get(int(event_id), 'active_directory')
        return 'active_directory'

    def _build_tags(self, parsed: dict) -> list:
        tags = ['windows', 'active_directory', 'security']
        event_id = parsed.get('event_id')
        if event_id: tags.append(f"event_id:{event_id}")
        if parsed.get('account_name'): tags.append(f"user:{parsed['account_name']}")
        if parsed.get('logon_type'): tags.append(f"logon_type:{parsed['logon_type']}")
        if parsed.get('failure_reason'): tags.append('auth_failure')
        return tags
