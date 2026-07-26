from django.db import models


SEVERITY_CHOICES = [
    ("critical", "Critical"),
    ("high", "High"),
    ("medium", "Medium"),
    ("low", "Low"),
    ("info", "Info"),
]

STATUS_CHOICES = [
    ("open", "Open"),
    ("investigating", "Investigating"),
    ("acknowledged", "Acknowledged"),
    ("resolved", "Resolved"),
    ("false_positive", "False Positive"),
]

MATCH_TYPE_CHOICES = [
    ("keyword", "Keyword"),
    ("regex", "Regular Expression"),
    ("metadata", "Metadata"),
]

TARGET_OS_CHOICES = [
    ("linux", "Linux"),
    ("windows", "Windows"),
]

SCAN_MODE_CHOICES = [
    ("all", "Todo el almacenamiento"),
    ("paths", "Rutas especificas"),
]

CHANNEL_CHOICES = [
    ("filesystem", "Filesystem"),
    ("downloads", "Downloads"),
    ("desktop", "Desktop"),
    ("documents", "Documents"),
    ("removable", "Removable Media"),
    ("network", "Network Share"),
    ("email", "Email"),
    ("clipboard", "Clipboard"),
    ("usb", "USB"),
    ("cloud", "Cloud Storage"),
    ("web", "Web Upload"),
]


class DlpPolicy(models.Model):
    code = models.SlugField(max_length=64, unique=True, help_text="Unique policy code")
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, default="")
    is_active = models.BooleanField(default=True, db_index=True)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default="high")
    scan_mode = models.CharField(max_length=16, choices=SCAN_MODE_CHOICES, default="all",
                                  help_text="'all' escanea todo el almacenamiento disponible incluyendo USBs")
    scan_paths = models.JSONField(default=list, blank=True)
    monitored_extensions = models.JSONField(default=list, blank=True)
    max_file_size_mb = models.IntegerField(default=25)
    max_scan_seconds = models.IntegerField(default=0, help_text="0 = sin limite de tiempo")
    target_os = models.CharField(max_length=32, choices=TARGET_OS_CHOICES, default="linux")
    realtime_enabled = models.BooleanField(default=True,
                                            help_text="Monitorear cambios en tiempo real (inotify/ReadDirectoryChangesW)")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "aegis_policies"
        ordering = ["-updated_at"]
        verbose_name = "DLP Policy"
        verbose_name_plural = "DLP Policies"

    def __str__(self):
        return f"{self.code}: {self.name} ({'active' if self.is_active else 'inactive'})"


class DlpRule(models.Model):
    policy = models.ForeignKey(DlpPolicy, on_delete=models.CASCADE, related_name="rules")
    name = models.CharField(max_length=255)
    pattern = models.TextField(help_text="Keyword or regex pattern to match")
    match_type = models.CharField(max_length=16, choices=MATCH_TYPE_CHOICES, default="keyword")
    classification = models.CharField(max_length=64, blank=True, default="")
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default="high")
    tags = models.JSONField(default=list, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "aegis_rules"
        ordering = ["policy", "name"]
        indexes = [
            models.Index(fields=["policy", "is_active"]),
        ]
        verbose_name = "DLP Rule"
        verbose_name_plural = "DLP Rules"

    def __str__(self):
        return f"{self.policy.code}/{self.name} ({self.match_type})"


class DlpThreat(models.Model):
    fingerprint = models.CharField(max_length=128, unique=True, db_index=True, help_text="SHA-256 dedup key")
    agent_id = models.CharField(max_length=128, blank=True, default="", db_index=True)
    agent_hostname = models.CharField(max_length=255, blank=True, default="")
    policy_code = models.SlugField(max_length=64, blank=True, default="", db_index=True)
    rule_name = models.CharField(max_length=255, blank=True, default="")
    classification = models.CharField(max_length=64, blank=True, default="", db_index=True)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default="high", db_index=True)
    status = models.CharField(max_length=24, choices=STATUS_CHOICES, default="open", db_index=True)
    file_name = models.CharField(max_length=512, blank=True, default="")
    file_path = models.TextField(blank=True, default="")
    file_hash = models.CharField(max_length=128, blank=True, default="")
    file_size = models.BigIntegerField(default=0)
    actor = models.CharField(max_length=255, blank=True, default="")
    channel = models.CharField(max_length=32, choices=CHANNEL_CHOICES, default="filesystem")
    summary = models.TextField(blank=True, default="")
    matched_keywords = models.JSONField(default=list, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    event_published = models.BooleanField(default=False, help_text="Published to service bus")
    evidence_file = models.FileField(
        upload_to="aegis/evidence/%Y/%m/%d/",
        blank=True,
        null=True,
        max_length=512,
        help_text="Uploaded copy of the file that triggered the threat",
    )
    detected_at = models.DateTimeField(db_index=True)
    acknowledged_at = models.DateTimeField(blank=True, null=True)
    acknowledged_by = models.CharField(max_length=255, blank=True, default="")
    resolved_at = models.DateTimeField(blank=True, null=True)
    resolved_by = models.CharField(max_length=255, blank=True, default="")
    resolution_notes = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = "aegis_threats"
        ordering = ["-detected_at"]
        indexes = [
            models.Index(fields=["severity", "status"]),
            models.Index(fields=["classification", "status"]),
            models.Index(fields=["agent_id", "detected_at"]),
        ]
        verbose_name = "DLP Threat"
        verbose_name_plural = "DLP Threats"

    def __str__(self):
        return f"[{self.severity}] {self.file_name} via {self.channel}"


class DlpScanSummary(models.Model):
    agent_id = models.CharField(max_length=128, blank=True, default="", db_index=True)
    agent_hostname = models.CharField(max_length=255, blank=True, default="")
    started_at = models.DateTimeField()
    finished_at = models.DateTimeField(blank=True, null=True)
    files_scanned = models.IntegerField(default=0)
    files_flagged = models.IntegerField(default=0)
    incidents_created = models.IntegerField(default=0)
    duration_seconds = models.FloatField(blank=True, null=True)
    status = models.CharField(max_length=16, default="completed", choices=[
        ("running", "Running"),
        ("completed", "Completed"),
        ("timeout", "Timeout"),
        ("error", "Error"),
    ])
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "aegis_scan_summaries"
        ordering = ["-started_at"]
        verbose_name = "DLP Scan Summary"
        verbose_name_plural = "DLP Scan Summaries"

    def __str__(self):
        return f"Agent {self.agent_id} scan {self.started_at} ({self.status})"
