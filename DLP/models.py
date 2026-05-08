from django.db import models

SEVERITY_CHOICES = [
    ('critical', 'Critical'),
    ('high', 'High'),
    ('medium', 'Medium'),
    ('low', 'Low'),
    ('info', 'Info'),
]

STATUS_CHOICES = [
    ('open', 'Open'),
    ('investigating', 'Investigating'),
    ('resolved', 'Resolved'),
    ('false_positive', 'False Positive'),
    ('acknowledged', 'Acknowledged'),
]

CHANNEL_CHOICES = [
    ('email', 'Email'),
    ('cloud', 'Cloud Storage'),
    ('web', 'Web Upload'),
    ('usb', 'USB/Removable'),
    ('network', 'Network Share'),
    ('documents', 'Documents Folder'),
    ('filesystem', 'Filesystem'),
]


class DlpPolicy(models.Model):
    code = models.CharField(max_length=64, unique=True, db_index=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, default='')
    enabled = models.BooleanField(default=True)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default='high')
    scan_paths = models.JSONField(default=list, blank=True)
    monitored_extensions = models.JSONField(default=list, blank=True)
    max_file_size_mb = models.IntegerField(default=25)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'dlp_policies'
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.code} - {self.name}'


class DlpRule(models.Model):
    policy = models.ForeignKey(DlpPolicy, on_delete=models.CASCADE, related_name='rules', db_index=True)
    name = models.CharField(max_length=255)
    pattern = models.TextField(help_text='Keyword or regex pattern to match')
    match_type = models.CharField(max_length=16, default='keyword', choices=[
        ('keyword', 'Keyword'),
        ('regex', 'Regex'),
        ('metadata', 'Metadata'),
    ])
    classification = models.CharField(max_length=64, blank=True, default='')
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default='high')
    tags = models.JSONField(default=list, blank=True)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'dlp_rules'
        indexes = [
            models.Index(fields=['policy', 'enabled']),
        ]

    def __str__(self):
        return f'{self.policy.code} / {self.name}'


class DlpIncident(models.Model):
    fingerprint = models.CharField(max_length=128, unique=True, db_index=True)
    remote_agent_id = models.CharField(max_length=128, blank=True, default='', db_index=True)
    host_name = models.CharField(max_length=255, blank=True, default='')
    policy_code = models.CharField(max_length=64, db_index=True)
    rule_name = models.CharField(max_length=255)
    classification = models.CharField(max_length=64, db_index=True)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default='high', db_index=True)
    status = models.CharField(max_length=24, choices=STATUS_CHOICES, default='open', db_index=True)
    file_name = models.CharField(max_length=512)
    file_path = models.TextField()
    file_hash = models.CharField(max_length=128, blank=True, default='')
    actor = models.CharField(max_length=255, blank=True, default='')
    channel = models.CharField(max_length=32, choices=CHANNEL_CHOICES, default='filesystem')
    summary = models.TextField(blank=True, default='')
    matched_keywords = models.JSONField(default=list, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    detected_at = models.DateTimeField(db_index=True)
    acknowledged_at = models.DateTimeField(blank=True, null=True)
    acknowledged_by = models.CharField(max_length=255, blank=True, default='')
    resolved_at = models.DateTimeField(blank=True, null=True)
    resolved_by = models.CharField(max_length=255, blank=True, default='')
    resolution_notes = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = 'dlp_incidents'
        ordering = ['-detected_at']
        indexes = [
            models.Index(fields=['severity', 'status']),
            models.Index(fields=['classification', 'status']),
            models.Index(fields=['remote_agent_id', 'detected_at']),
            models.Index(fields=['file_path']),
        ]

    def __str__(self):
        return f'[{self.severity}] {self.policy_code} - {self.file_name}'


class DlpScanSummary(models.Model):
    remote_agent_id = models.CharField(max_length=128, blank=True, default='', db_index=True)
    host_name = models.CharField(max_length=255, blank=True, default='')
    started_at = models.DateTimeField()
    finished_at = models.DateTimeField(blank=True, null=True)
    files_scanned = models.IntegerField(default=0)
    files_flagged = models.IntegerField(default=0)
    incidents_created = models.IntegerField(default=0)
    duration_seconds = models.FloatField(blank=True, null=True)
    status = models.CharField(max_length=16, default='completed', choices=[
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('timeout', 'Timeout'),
        ('error', 'Error'),
    ])
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'dlp_scan_summaries'
        ordering = ['-started_at']

    def __str__(self):
        return f'{self.remote_agent_id} scan {self.started_at} ({self.status})'
