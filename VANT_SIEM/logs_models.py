"""
Log models for VANT-SIEM
Reflects the actual os_events_raw schema used by the ingestion pipeline
"""
from django.db import models
from django.utils import timezone


class LogEvent(models.Model):
    """Unified log entry from any source (snort, suricata, firewall, dhcp, filelogs)"""
    source_type = models.CharField(max_length=50, db_index=True, help_text="snort, suricata, firewall, dhcp, filelog")
    source_name = models.CharField(max_length=100, blank=True, default="")
    host_name = models.CharField(max_length=200, blank=True, default="")
    host_ip = models.GenericIPAddressField(blank=True, null=True)
    event_time = models.DateTimeField(db_index=True, default=timezone.now)
    severity = models.CharField(max_length=20, db_index=True, default="info")
    event_category = models.CharField(max_length=100, blank=True, default="")
    message = models.TextField(blank=True, default="")
    raw_payload = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=list, blank=True)
    ingested_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = "os_events_raw"
        ordering = ["-event_time"]
        indexes = [
            models.Index(fields=["event_time", "source_type"]),
            models.Index(fields=["event_time", "severity"]),
            models.Index(fields=["host_ip", "event_time"]),
        ]

    def __str__(self):
        return f"[{self.source_type}] {self.severity} - {self.message[:80]}"


class LogSource(models.Model):
    """Registered log source (agent or collector)"""
    source_id = models.CharField(max_length=100, unique=True, primary_key=True)
    source_type = models.CharField(max_length=50, default="")
    host_name = models.CharField(max_length=200, blank=True, default="")
    enabled = models.BooleanField(default=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    meta = models.JSONField(default=dict, blank=True)
    registered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "os_sources"
        ordering = ["-last_seen_at"]

    def __str__(self):
        return f"{self.source_id} ({self.source_type})"
