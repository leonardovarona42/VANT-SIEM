import logging
from django.db import models
from django.utils import timezone

logger = logging.getLogger(__name__)

SOURCE_TYPE_CHOICES = [
    ('firewall_huawei', 'Huawei Firewall (USG/eudemon)'),
    ('snort', 'Snort IDS'),
    ('suricata', 'Suricata IDS'),
    ('windows_ad', 'Windows Active Directory'),
    ('windows_dhcp', 'Windows DHCP'),
    ('windows_dns', 'Windows DNS'),
    ('samba', 'Samba / Linux File Server'),
    ('switch', 'Network Switch'),
    ('router', 'Router'),
    ('modem', 'Modem'),
    ('agent_filelog', 'Agent File Log (Linux/Windows)'),
    ('generic_syslog', 'Generic Syslog'),
    ('firewall_cisco', 'Cisco Firewall (ASA/Firepower)'),
    ('fortigate', 'Fortinet FortiGate'),
    ('paloalto', 'Palo Alto Networks'),
]

PROTOCOL_CHOICES = [
    ('syslog', 'Syslog (UDP/TCP)'),
    ('http_post', 'HTTP POST (JSON)'),
    ('agent_push', 'Agent Push (HTTPS)'),
    ('snmp_trap', 'SNMP Trap'),
    ('file_poll', 'File Polling'),
    ('api_pull', 'API Pull'),
]

SEVERITY_CHOICES = [
    ('critical', 'Critical'),
    ('high', 'High'),
    ('medium', 'Medium'),
    ('low', 'Low'),
    ('info', 'Info'),
    ('debug', 'Debug'),
]

VENDOR_CHOICES = [
    ('Huawei', 'Huawei'),
    ('Cisco', 'Cisco'),
    ('Microsoft', 'Microsoft'),
    ('Linux', 'Linux'),
    ('Palo Alto', 'Palo Alto Networks'),
    ('Fortinet', 'Fortinet'),
    ('Check Point', 'Check Point'),
    ('SonicWall', 'SonicWall'),
    ('Juniper', 'Juniper'),
    ('OpenSource', 'Open Source'),
    ('Unknown', 'Unknown'),
]


class LogSource(models.Model):
    source_id = models.CharField(max_length=128, primary_key=True, db_index=True)
    source_type = models.CharField(max_length=64, choices=SOURCE_TYPE_CHOICES)
    vendor = models.CharField(max_length=64, choices=VENDOR_CHOICES, default='Unknown')
    model = models.CharField(max_length=128, blank=True, default='')
    host_name = models.CharField(max_length=255, blank=True, default='')
    host_ip = models.GenericIPAddressField(blank=True, null=True)
    protocol = models.CharField(max_length=32, choices=PROTOCOL_CHOICES, default='syslog')
    port = models.IntegerField(blank=True, null=True)
    api_key = models.CharField(max_length=256, blank=True, default='')
    enabled = models.BooleanField(default=True)
    meta = models.JSONField(default=dict, blank=True)
    registered_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = 'logs_sources'
        indexes = [
            models.Index(fields=['source_type', 'enabled']),
            models.Index(fields=['vendor']),
            models.Index(fields=['host_ip']),
        ]

    def __str__(self):
        return f'{self.source_id} ({self.source_type})'

    def touch(self):
        self.last_seen_at = timezone.now()
        self.save(update_fields=['last_seen_at'])


class LogEventRaw(models.Model):
    id = models.BigAutoField(primary_key=True)
    source = models.ForeignKey(LogSource, on_delete=models.SET_NULL, null=True, blank=True, related_name='events', db_index=True)
    source_type = models.CharField(max_length=64, choices=SOURCE_TYPE_CHOICES, db_index=True)
    host_name = models.CharField(max_length=255, blank=True, default='', db_index=True)
    host_ip = models.GenericIPAddressField(blank=True, null=True)
    event_time = models.DateTimeField(db_index=True)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default='info', db_index=True)
    event_category = models.CharField(max_length=128, default='unknown', db_index=True)
    message = models.TextField(blank=True, default='')
    raw_payload = models.JSONField(default=dict, blank=True)
    parsed_fields = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=list, blank=True)
    ingested_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = 'logs_events_raw'
        indexes = [
            models.Index(fields=['event_time', 'source_type']),
            models.Index(fields=['event_time', 'severity']),
            models.Index(fields=['host_ip', 'event_time']),
            models.Index(fields=['severity', 'event_category']),
            models.Index(fields=['event_category', 'event_time']),
        ]

    def __str__(self):
        return f'[{self.severity}] {self.source_type} - {self.event_time}'

    @classmethod
    def create_from_parsed(cls, source, parsed: dict, raw_message: str, event_time=None):
        return cls(
            source=source,
            source_type=parsed.get('source_type', source.source_type if source else 'unknown'),
            host_name=parsed.get('hostname', ''),
            host_ip=parsed.get('host_ip'),
            event_time=event_time or timezone.now(),
            severity=parsed.get('severity', 'info'),
            event_category=parsed.get('event_category', 'unknown'),
            message=raw_message[:5000],
            raw_payload={'raw': raw_message},
            parsed_fields=parsed.get('parsed_fields', {}),
            tags=parsed.get('tags', []),
        )

    @classmethod
    def bulk_create_events(cls, events_list):
        if not events_list:
            return 0
        batch_size = 1000
        total = 0
        for i in range(0, len(events_list), batch_size):
            batch = events_list[i:i + batch_size]
            cls.objects.bulk_create(batch, batch_size=batch_size)
            total += len(batch)
        return total


class LogRetentionPolicy(models.Model):
    source_type = models.CharField(max_length=64, unique=True, choices=SOURCE_TYPE_CHOICES)
    retention_days = models.IntegerField(default=90)
    auto_delete = models.BooleanField(default=True)
    last_cleanup_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'logs_retention_policies'

    def __str__(self):
        return f'{self.source_type}: {self.retention_days} days'
