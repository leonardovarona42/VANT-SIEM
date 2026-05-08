import uuid
from django.db import models
from django.utils import timezone


DLP_SEVERITY_CHOICES = [
    ("low", "Low"),
    ("medium", "Medium"),
    ("high", "High"),
    ("critical", "Critical"),
]

DLP_MATCH_TYPE_CHOICES = [
    ("keyword", "Keyword"),
    ("regex", "Regular Expression"),
    ("metadata", "Metadata"),
]

DLP_CHANNEL_CHOICES = [
    ("filesystem", "Filesystem"),
    ("downloads", "Downloads"),
    ("desktop", "Desktop"),
    ("documents", "Documents"),
    ("removable", "Removable Media"),
    ("network", "Network Share"),
    ("email", "Email"),
    ("clipboard", "Clipboard"),
    ("usb", "USB"),
]


class DlpPolicy(models.Model):
    """A DLP policy containing rules that the agents evaluate."""

    code = models.SlugField(max_length=64, unique=True, help_text="Unique policy code (e.g. aegis-local-shield)")
    name = models.CharField(max_length=255, help_text="Human-readable policy name")
    description = models.TextField(blank=True, default="")
    severity = models.CharField(max_length=16, choices=DLP_SEVERITY_CHOICES, default="high")
    is_active = models.BooleanField(default=True, db_index=True)
    scan_paths = models.JSONField(default=list, blank=True, help_text="Paths to scan on agents")
    monitored_extensions = models.JSONField(default=list, blank=True, help_text="File extensions to scan (e.g. .docx, .pdf)")
    max_file_size_mb = models.IntegerField(default=25, help_text="Max file size in MB to scan")
    max_scan_seconds = models.IntegerField(default=20, help_text="Max scan duration per agent cycle")
    target_os = models.CharField(max_length=32, blank=True, default="", help_text="Target OS: windows, linux, or empty for all")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "assets_dlp_policies"
        ordering = ["-updated_at"]
        verbose_name = "DLP Policy"
        verbose_name_plural = "DLP Policies"

    def __str__(self):
        return f"{self.code}: {self.name} ({'active' if self.is_active else 'inactive'})"


class DlpRule(models.Model):
    """A detection rule within a DLP policy."""

    policy = models.ForeignKey(DlpPolicy, on_delete=models.CASCADE, related_name="rules")
    name = models.CharField(max_length=255, help_text="Rule name (e.g. 'Clasificado', 'Confidential')")
    classification = models.SlugField(max_length=64, help_text="Classification tag applied on match")
    severity = models.CharField(max_length=16, choices=DLP_SEVERITY_CHOICES, default="high")
    match_type = models.CharField(max_length=16, choices=DLP_MATCH_TYPE_CHOICES, default="keyword")
    pattern = models.TextField(help_text="Keyword or regex pattern to match")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "assets_dlp_rules"
        ordering = ["policy", "name"]
        verbose_name = "DLP Rule"
        verbose_name_plural = "DLP Rules"

    def __str__(self):
        return f"{self.policy.code}/{self.name} ({self.match_type})"


class DlpThreat(models.Model):
    """
    Raw DLP detection reported by an agent.

    This is NOT an incident — it is a threat observation.
    The ASSETS service publishes an event via the service bus,
    and EVENT_M subscribes to create the actual Incident + Reporte.
    """

    fingerprint = models.CharField(max_length=128, unique=True, db_index=True, help_text="SHA-256 dedup key")
    agent_id = models.UUIDField(db_index=True, help_text="Agent that reported this threat")
    agent_hostname = models.CharField(max_length=255, blank=True, default="")
    policy_code = models.SlugField(max_length=64, blank=True, default="")
    rule_name = models.CharField(max_length=255, blank=True, default="")
    classification = models.SlugField(max_length=64, blank=True, default="")
    severity = models.CharField(max_length=16, choices=DLP_SEVERITY_CHOICES, default="high")
    file_name = models.CharField(max_length=512, blank=True, default="")
    file_path = models.TextField(blank=True, default="")
    file_hash = models.CharField(max_length=128, blank=True, default="")
    file_size = models.BigIntegerField(default=0)
    actor = models.CharField(max_length=255, blank=True, default="", help_text="File owner / user")
    channel = models.CharField(max_length=32, choices=DLP_CHANNEL_CHOICES, default="filesystem")
    summary = models.TextField(blank=True, default="")
    matched_keywords = models.JSONField(default=list, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    event_published = models.BooleanField(default=False, help_text="Whether the DLP event was published to the service bus")
    detected_at = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "assets_dlp_threats"
        ordering = ["-detected_at"]
        indexes = [
            models.Index(fields=["severity"]),
            models.Index(fields=["classification"]),
            models.Index(fields=["agent_id", "detected_at"]),
        ]
        verbose_name = "DLP Threat"
        verbose_name_plural = "DLP Threats"

    def __str__(self):
        return f"[{self.severity}] {self.file_name} via {self.channel}"
