from django.db import models


class AlertChannel(models.Model):
    TYPE_CHOICES = [
        ("email", "Email"),
        ("telegram", "Telegram"),
        ("webhook", "Webhook"),
    ]
    id = models.BigAutoField(primary_key=True)
    name = models.CharField(max_length=128)
    channel_type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    config = models.JSONField(default=dict)
    is_active = models.BooleanField(default=True)
    severity_filter = models.JSONField(
        default=list, help_text="List of severities to alert on"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "bus_alert_channels"

    def __str__(self):
        return f"{self.name} ({self.channel_type})"


class AlertHistory(models.Model):
    id = models.BigAutoField(primary_key=True)
    severity = models.CharField(max_length=16)
    title = models.CharField(max_length=255)
    message = models.TextField()
    source = models.CharField(max_length=128, blank=True, default="")
    channel = models.CharField(max_length=20, blank=True, default="")
    status = models.CharField(max_length=16, default="sent")
    metadata = models.JSONField(default=dict)
    sent_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "bus_alert_history"
        ordering = ["-sent_at"]

    def __str__(self):
        return f"[{self.severity}] {self.title}"
