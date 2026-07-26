import uuid
import logging
from datetime import timedelta
from django.db import models
from django.utils import timezone

logger = logging.getLogger(__name__)

OS_CHOICES = [
    ('windows_10', 'Windows 10'),
    ('windows_11', 'Windows 11'),
    ('windows_server_2019', 'Windows Server 2019'),
    ('windows_server_2022', 'Windows Server 2022'),
    ('windows_server_2025', 'Windows Server 2025'),
    ('ubuntu_22_04', 'Ubuntu 22.04'),
    ('ubuntu_24_04', 'Ubuntu 24.04'),
    ('debian_12', 'Debian 12'),
    ('rhel_8', 'RHEL 8'),
    ('rhel_9', 'RHEL 9'),
    ('centos_9', 'CentOS Stream 9'),
    ('macos_14', 'macOS 14'),
    ('macos_15', 'macOS 15'),
    ('other_linux', 'Other Linux'),
    ('other', 'Other'),
]

STATUS_CHOICES = [
    ('online', 'Online'),
    ('offline', 'Offline'),
    ('pending', 'Pending Registration'),
    ('error', 'Error'),
    ('disabled', 'Disabled'),
]

COMMAND_STATUS_CHOICES = [
    ('pending', 'Pending'),
    ('sent', 'Sent'),
    ('received', 'Received by Agent'),
    ('completed', 'Completed'),
    ('failed', 'Failed'),
    ('cancelled', 'Cancelled'),
]

COMMAND_TYPE_CHOICES = [
    ('update_inventory', 'Update Inventory'),
    ('restart_agent', 'Restart Agent'),
    ('stop_agent', 'Stop Agent'),
    ('update_agent', 'Update Agent'),
    ('run_script', 'Run Script'),
    ('collect_logs', 'Collect Logs'),
    ('collect_processes', 'Collect Processes & Ports'),
    ('push_config', 'Push Configuration'),
    ('start_screen_share', 'Start Screen Sharing'),
    ('stop_screen_share', 'Stop Screen Sharing'),
    ('list_services', 'List System Services'),
    ('list_apt_updates', 'Check APT Updates'),
    ('custom', 'Custom'),
]


class Agent(models.Model):
    agent_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    hostname = models.CharField(max_length=255, db_index=True)
    machine_name = models.CharField(max_length=255, blank=True, default='')
    os_type = models.CharField(max_length=64, choices=OS_CHOICES, default='other')
    os_version = models.CharField(max_length=128, blank=True, default='')
    os_arch = models.CharField(max_length=16, default='x86_64')
    agent_version = models.CharField(max_length=32, default='1.0.0')
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    mac_address = models.CharField(max_length=17, blank=True, default='')
    domain = models.CharField(max_length=255, blank=True, default='')
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default='pending', db_index=True)
    last_heartbeat = models.DateTimeField(blank=True, null=True)
    registered_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_inventory_at = models.DateTimeField(blank=True, null=True)
    meta = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=list, blank=True)

    class Meta:
        db_table = 'inventory_agents'
        indexes = [
            models.Index(fields=['hostname', 'status']),
            models.Index(fields=['os_type']),
            models.Index(fields=['ip_address']),
            models.Index(fields=['status', 'last_heartbeat']),
        ]

    def __str__(self):
        return f'{self.hostname} ({self.agent_id}) [{self.status}]'

    def heartbeat(self):
        self.last_heartbeat = timezone.now()
        if self.status in ('offline', 'pending'):
            self.status = 'online'
        self.save(update_fields=['last_heartbeat', 'status', 'updated_at'])

    def go_offline(self):
        self.status = 'offline'
        self.save(update_fields=['status', 'updated_at'])

    @classmethod
    def mark_stale_offline(cls, minutes=15):
        threshold = timezone.now() - timedelta(minutes=minutes)
        updated = cls.objects.filter(last_heartbeat__lt=threshold, status='online').update(
            status='offline', updated_at=timezone.now()
        )
        if updated:
            logger.info("Marked %s stale agents as offline", updated)
        return updated


class HardwareInventory(models.Model):
    agent = models.OneToOneField(Agent, on_delete=models.CASCADE, related_name='hardware')
    cpu_model = models.CharField(max_length=255, blank=True, default='')
    cpu_cores = models.IntegerField(default=0)
    cpu_threads = models.IntegerField(default=0)
    cpu_speed_ghz = models.FloatField(default=0)
    ram_total_gb = models.FloatField(default=0)
    ram_slots_used = models.IntegerField(default=0)
    ram_slots_total = models.IntegerField(default=0)
    motherboard_model = models.CharField(max_length=255, blank=True, default='')
    motherboard_manufacturer = models.CharField(max_length=255, blank=True, default='')
    bios_version = models.CharField(max_length=128, blank=True, default='')
    gpu_models = models.JSONField(default=list, blank=True)
    disks = models.JSONField(default=list, blank=True)
    network_interfaces = models.JSONField(default=list, blank=True)
    serial_number = models.CharField(max_length=128, blank=True, default='')
    manufacturer = models.CharField(max_length=255, blank=True, default='')
    product_name = models.CharField(max_length=255, blank=True, default='')
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'inventory_hardware'

    def __str__(self):
        return f'Hardware: {self.agent.hostname}'

    @staticmethod
    def _parse_size_to_gb(value):
        if not value:
            return 0.0
        if isinstance(value, (int, float)):
            return float(value)
        s = str(value).strip().upper()
        if not s:
            return 0.0
        try:
            return float(s)
        except ValueError:
            pass
        multipliers = {'K': 1 / (1024 * 1024), 'M': 1 / 1024, 'G': 1, 'T': 1024}
        for suffix, factor in multipliers.items():
            if s.endswith(suffix):
                try:
                    return float(s[:-1]) * factor
                except ValueError:
                    return 0.0
        try:
            return float(s)
        except ValueError:
            return 0.0

    @property
    def disk_total_gb(self):
        return sum(self._parse_size_to_gb(d.get('size_gb', 0)) for d in self.disks)

    @property
    def disks_parsed(self):
        result = []
        for d in self.disks:
            d = dict(d)
            d['size_gb_numeric'] = self._parse_size_to_gb(d.get('size_gb', 0))
            result.append(d)
        return result

    @property
    def ram_used_gb(self):
        return self.ram_total_gb - sum(self._parse_size_to_gb(d.get('available_gb', 0)) for d in self.ram_modules or [])


class SoftwareInventory(models.Model):
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='software')
    name = models.CharField(max_length=255, db_index=True)
    version = models.CharField(max_length=128, blank=True, default='')
    publisher = models.CharField(max_length=255, blank=True, default='')
    install_date = models.DateField(blank=True, null=True)
    install_location = models.CharField(max_length=512, blank=True, default='')
    software_type = models.CharField(max_length=64, default='application', db_index=True)
    size_mb = models.FloatField(default=0)
    is_system = models.BooleanField(default=False)
    last_seen_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'inventory_software'
        indexes = [
            models.Index(fields=['agent', 'name']),
            models.Index(fields=['name', 'version']),
            models.Index(fields=['software_type']),
            models.Index(fields=['is_system']),
        ]
        unique_together = ['agent', 'name', 'version', 'publisher']

    def __str__(self):
        return f'{self.name} {self.version} on {self.agent.hostname}'


class AgentCommand(models.Model):
    command_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='commands')
    command_type = models.CharField(max_length=32, choices=COMMAND_TYPE_CHOICES)
    payload = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=16, choices=COMMAND_STATUS_CHOICES, default='pending', db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    sent_at = models.DateTimeField(blank=True, null=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    result = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True, default='')

    class Meta:
        db_table = 'inventory_commands'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['agent', 'status']),
            models.Index(fields=['status', 'created_at']),
        ]

    def __str__(self):
        return f'Command {self.command_type} -> {self.agent.hostname} [{self.status}]'

    def mark_sent(self):
        self.status = 'sent'
        self.sent_at = timezone.now()
        self.save(update_fields=['status', 'sent_at'])

    def mark_completed(self, result=None):
        self.status = 'completed'
        self.completed_at = timezone.now()
        if result:
            self.result = result
        self.save(update_fields=['status', 'completed_at', 'result'])

    def mark_failed(self, error=''):
        self.status = 'failed'
        self.completed_at = timezone.now()
        self.error_message = error
        self.save(update_fields=['status', 'completed_at', 'error_message'])


class ScreenCapture(models.Model):
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='screenshots')
    image = models.TextField()
    captured_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'screen_captures'
        ordering = ['-captured_at']
        indexes = [
            models.Index(fields=['agent', '-captured_at']),
        ]


class ProcessSnapshot(models.Model):
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='process_snapshots')
    processes = models.JSONField(default=list)
    connections = models.JSONField(default=list)
    captured_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'process_snapshots'
        ordering = ['-captured_at']
        indexes = [
            models.Index(fields=['agent', '-captured_at']),
        ]
