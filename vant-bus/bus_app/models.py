from django.db import models


class SystemEvent(models.Model):
    EVENT_TYPE_CHOICES = [
        ("reporte_creado", "Reporte Creado"),
        ("reporte_editado", "Reporte Editado"),
        ("reporte_eliminado", "Reporte Eliminado"),
        ("reporte_rechazado", "Reporte Rechazado"),
        ("incidente_creado", "Incidente Creado"),
        ("incidente_editado", "Incidente Editado"),
        ("incidente_estado_cambiado", "Incidente Estado Cambiado"),
        ("incidente_eliminado", "Incidente Eliminado"),
        ("login_exitoso", "Login Exitoso"),
        ("login_fallido", "Login Fallido"),
        ("login_bloqueado", "Login Bloqueado"),
        ("usuario_creado", "Usuario Creado"),
        ("usuario_desabilitado", "Usuario Deshabilitado"),
        ("servicio_down", "Servicio Down"),
        ("servicio_up", "Servicio Up"),
        ("servicio_restart", "Servicio Restart"),
        ("servicio_stop", "Servicio Stop"),
        ("agente_conectado", "Agente Conectado"),
        ("agente_desconectado", "Agente Desconectado"),
        ("amenaza_dlp", "Amenaza DLP"),
        ("servicio_fallo", "Servicio Caído"),
        ("servicio_recuperado", "Servicio Recuperado"),
        ("paquete_actualizacion", "Paquete Actualización"),
    ]

    SEVERITY_CHOICES = [
        ("info", "Info"),
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]

    id = models.BigAutoField(primary_key=True)
    event_type = models.CharField(max_length=40, choices=EVENT_TYPE_CHOICES, db_index=True)
    source_service = models.CharField(max_length=32, db_index=True)
    entity_type = models.CharField(max_length=32, blank=True, default="", db_index=True)
    entity_id = models.CharField(max_length=64, blank=True, default="")
    actor_user_id = models.CharField(max_length=64, blank=True, default="")
    actor_username = models.CharField(max_length=150, blank=True, default="")
    payload = models.JSONField(default=dict)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default="info", db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    processed = models.BooleanField(default=False)

    class Meta:
        db_table = "bus_system_events"
        ordering = ["-created_at"]

    def __str__(self):
        return f"[{self.severity}] {self.event_type} ({self.source_service})"


class NotificationGroup(models.Model):
    id = models.BigAutoField(primary_key=True)
    name = models.CharField(max_length=128, unique=True)
    description = models.TextField(blank=True, default="")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "bus_notification_groups"
        ordering = ["name"]

    def __str__(self):
        return self.name


class GroupMember(models.Model):
    id = models.BigAutoField(primary_key=True)
    group = models.ForeignKey(NotificationGroup, on_delete=models.CASCADE, related_name="members")
    user_id = models.CharField(max_length=64, db_index=True)
    username = models.CharField(max_length=150)
    email = models.EmailField(max_length=254, blank=True, default="")
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "bus_group_members"
        unique_together = [("group", "user_id")]

    def __str__(self):
        return f"{self.username} → {self.group.name}"


class GroupAlertSubscription(models.Model):
    CHANNEL_CHOICES = [
        ("email", "Email"),
        ("dashboard", "Dashboard"),
        ("telegram", "Telegram"),
        ("webhook", "Webhook"),
    ]

    id = models.BigAutoField(primary_key=True)
    group = models.ForeignKey(NotificationGroup, on_delete=models.CASCADE, related_name="subscriptions")
    event_type = models.CharField(max_length=40, db_index=True)
    channel = models.CharField(max_length=20, choices=CHANNEL_CHOICES, default="dashboard")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "bus_group_alert_subscriptions"
        unique_together = [("group", "event_type", "channel")]

    def __str__(self):
        return f"{self.group.name} → {self.event_type} via {self.channel}"


class EmailConfig(models.Model):
    id = models.BigAutoField(primary_key=True)
    smtp_host = models.CharField(max_length=255, default="smtp.gmail.com")
    smtp_port = models.IntegerField(default=587)
    smtp_user = models.CharField(max_length=255, blank=True, default="")
    smtp_password = models.CharField(max_length=255, blank=True, default="")
    use_tls = models.BooleanField(default=True)
    from_address = models.EmailField(default="vant-alerts@example.com")
    is_active = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "bus_email_config"

    def __str__(self):
        return f"Email Config ({self.smtp_host}:{self.smtp_port})"


class NotificationLog(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("sent", "Sent"),
        ("failed", "Failed"),
        ("read", "Read"),
    ]

    id = models.BigAutoField(primary_key=True)
    event = models.ForeignKey(SystemEvent, on_delete=models.CASCADE, related_name="notifications")
    group = models.ForeignKey(NotificationGroup, on_delete=models.SET_NULL, null=True, related_name="notifications")
    channel = models.CharField(max_length=20, default="dashboard")
    recipient_user_id = models.CharField(max_length=64, blank=True, default="")
    recipient_email = models.EmailField(blank=True, default="")
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default="pending", db_index=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    read_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "bus_notification_logs"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.event.event_type} → {self.group} ({self.status})"


class ServiceConfig(models.Model):
    id = models.BigAutoField(primary_key=True)
    name = models.CharField(max_length=64, unique=True)
    display_name = models.CharField(max_length=128)
    host = models.CharField(max_length=128, default="127.0.0.1")
    port = models.IntegerField()
    health_endpoint = models.CharField(max_length=128, default="/api/health/")
    systemd_service = models.CharField(max_length=64)
    is_critical = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    last_health_check = models.DateTimeField(null=True, blank=True)
    last_health_status = models.CharField(max_length=20, default="unknown")
    consecutive_failures = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "bus_service_configs"
        ordering = ["name"]

    def __str__(self):
        return f"{self.display_name} ({self.last_health_status})"


class ServiceHealthLog(models.Model):
    id = models.BigAutoField(primary_key=True)
    service = models.ForeignKey(ServiceConfig, on_delete=models.CASCADE, related_name="health_logs")
    status = models.CharField(max_length=20)
    response_time_ms = models.IntegerField(null=True, blank=True)
    details = models.JSONField(default=dict)
    checked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "bus_service_health_logs"
        ordering = ["-checked_at"]


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
    severity_filter = models.JSONField(default=list, help_text="List of severities to alert on")
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
