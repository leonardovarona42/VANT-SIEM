import json
import re
from .base import BaseParser

class SambaParser(BaseParser):
    source_type = 'samba'

    _USER_RE = re.compile(r'(?:user|account|username)[=:\s]+([^\s,;]+)', re.IGNORECASE)
    _SHARE_RE = re.compile(r'(?:share|path|service)[=:\s]+([^\s,;]+)', re.IGNORECASE)
    _FILE_RE = re.compile(r'(?:file|filename|path)[=:\s]+([^\s,;]+)', re.IGNORECASE)
    _ACTION_RE = re.compile(r'(?:action|operation|op)[=:\s]+(\w+)', re.IGNORECASE)
    _CLIENT_RE = re.compile(r'(?:client|src|source)[=:\s]+([\d.]+)', re.IGNORECASE)

    def _extract_fields(self, raw: str) -> dict:
        fields = {}
        try:
            data = json.loads(raw)
            fields['service'] = data.get('service') or data.get('Service') or data.get('smb_service', 'smbd')
            fields['user'] = data.get('user') or data.get('User') or data.get('username')
            fields['share'] = data.get('share') or data.get('Share') or data.get('share_name')
            fields['file'] = data.get('file') or data.get('File') or data.get('filename') or data.get('path')
            fields['action'] = data.get('action') or data.get('Action') or data.get('operation')
            fields['client_ip'] = data.get('client_ip') or data.get('ClientIP') or data.get('source_ip')
            fields['host_ip'] = fields.get('client_ip')
            fields['status'] = data.get('status') or data.get('Status') or data.get('result')
            return fields
        except (json.JSONDecodeError, ValueError):
            pass
        m = self._USER_RE.search(raw)
        if m: fields['user'] = m.group(1)
        m = self._SHARE_RE.search(raw)
        if m: fields['share'] = m.group(1)
        m = self._FILE_RE.search(raw)
        if m: fields['file'] = m.group(1)
        m = self._ACTION_RE.search(raw)
        if m: fields['action'] = m.group(1)
        m = self._CLIENT_RE.search(raw)
        if m: fields['client_ip'] = m.group(1)
        fields['host_ip'] = fields.get('client_ip') or self._extract_ip(raw)
        if 'smbd' in raw.lower(): fields['service'] = 'smbd'
        elif 'nmbd' in raw.lower(): fields['service'] = 'nmbd'
        elif 'winbind' in raw.lower(): fields['service'] = 'winbindd'
        return fields

    def _guess_category(self, parsed: dict) -> str:
        action = (parsed.get('action') or '').lower()
        if action in ('delete', 'removed', 'unlink'): return 'file_deletion'
        if action in ('create', 'write', 'new', 'modified'): return 'file_modification'
        if action in ('read', 'open', 'access'): return 'file_access'
        if action in ('auth', 'login', 'logon'): return 'authentication'
        if parsed.get('service') == 'smbd': return 'smb'
        if parsed.get('service') == 'winbindd': return 'winbind'
        return 'samba'

    def _build_tags(self, parsed: dict) -> list:
        tags = ['samba', 'linux', parsed.get('service', 'smbd')]
        action = parsed.get('action', '').lower()
        if action: tags.append(action)
        if parsed.get('share'): tags.append(f"share:{parsed['share']}")
        if parsed.get('user'): tags.append(f"user:{parsed['user']}")
        return tags
