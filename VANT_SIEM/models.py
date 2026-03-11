import uuid
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

# ===== MODELOS PARA NOTIFICACIONES MEJORADAS =====

import uuid
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

# ===== MODELOS PARA NOTIFICACIONES =====

class Notification(models.Model):
    """Modelo para notificaciones del sistema"""

    NOTIFICATION_TYPES = [
        ('USER_CREATE_REQUEST', 'Solicitud de Creación de Usuario'),
        ('USER_APPROVAL_REQUEST', 'Solicitud de Aprobación de Usuario'),
        ('CRITICAL_OPERATION', 'Operación Crítica'),
        ('SYSTEM_ALERT', 'Alerta del Sistema'),
        ('DATA_CHANGE', 'Cambio de Datos'),
        ('SECURITY_EVENT', 'Evento de Seguridad'),
        ('BACKUP_COMPLETE', 'Respaldo Completado'),
        ('MAINTENANCE', 'Mantenimiento'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    title = models.CharField(max_length=200)
    message = models.TextField()
    event_type = models.CharField(max_length=50, choices=NOTIFICATION_TYPES)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    read_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Notificación'
        verbose_name_plural = 'Notificaciones'

    def __str__(self):
        return f"{self.title} - {self.user.username}"

    def mark_as_read(self):
        self.is_read = True
        self.read_at = timezone.now()
        self.save()

# ===== MODELOS PARA NOTIFICACIONES MEJORADAS =====

class NotificationTemplate(models.Model):
    """Plantillas para notificaciones personalizables"""

    TEMPLATE_TYPES = [
        ('EMAIL', 'Email'),
        ('SMS', 'SMS'),
        ('SLACK', 'Slack'),
        ('TEAMS', 'Microsoft Teams'),
        ('WEBHOOK', 'Webhook'),
        ('BROWSER_PUSH', 'Notificación Push del Navegador'),
    ]

    name = models.CharField(max_length=100, unique=True, help_text="Nombre único de la plantilla")
    template_type = models.CharField(max_length=20, choices=TEMPLATE_TYPES)
    event_type = models.CharField(max_length=50, choices=Notification.NOTIFICATION_TYPES)
    subject_template = models.CharField(max_length=255, blank=True, help_text="Plantilla del asunto (solo para email)")
    body_template = models.TextField(help_text="Plantilla del cuerpo del mensaje")

    # Variables disponibles en la plantilla
    available_variables = models.JSONField(default=dict, help_text="Variables disponibles para esta plantilla")

    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Plantilla de Notificación'
        verbose_name_plural = 'Plantillas de Notificación'
        unique_together = ['template_type', 'event_type']

    def __str__(self):
        return f"{self.name} ({self.get_template_type_display()})"


class NotificationChannel(models.Model):
    """Configuración de canales de notificación adicionales"""

    CHANNEL_TYPES = [
        ('SMS', 'SMS'),
        ('SLACK', 'Slack'),
        ('TEAMS', 'Microsoft Teams'),
        ('WEBHOOK', 'Webhook'),
        ('BROWSER_PUSH', 'Notificación Push del Navegador'),
    ]

    name = models.CharField(max_length=100, unique=True)
    channel_type = models.CharField(max_length=20, choices=CHANNEL_TYPES)
    is_active = models.BooleanField(default=True)

    # Configuración específica por canal
    config = models.JSONField(default=dict, help_text="Configuración específica del canal")

    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Canal de Notificación'
        verbose_name_plural = 'Canales de Notificación'

    def __str__(self):
        return f"{self.name} ({self.get_channel_type_display()})"


class NotificationQueue(models.Model):
    """Cola de notificaciones para procesamiento asíncrono"""

    STATUS_CHOICES = [
        ('PENDING', 'Pendiente'),
        ('PROCESSING', 'Procesando'),
        ('SENT', 'Enviada'),
        ('FAILED', 'Fallida'),
        ('RETRY', 'Reintentar'),
    ]

    notification = models.ForeignKey(Notification, on_delete=models.CASCADE)
    channel = models.ForeignKey(NotificationChannel, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    priority = models.IntegerField(default=1, help_text="Prioridad (1-5, 5 es más alta)")

    # Reintentos
    retry_count = models.IntegerField(default=0)
    max_retries = models.IntegerField(default=3)

    # Programación
    scheduled_at = models.DateTimeField(null=True, blank=True)
    sent_at = models.DateTimeField(null=True, blank=True)

    # Metadatos
    error_message = models.TextField(blank=True)
    metadata = models.JSONField(default=dict)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Notificación en Cola'
        verbose_name_plural = 'Notificaciones en Cola'
        ordering = ['-priority', 'created_at']
        indexes = [
            models.Index(fields=['status', 'priority']),
            models.Index(fields=['scheduled_at']),
        ]

    def __str__(self):
        return f"Queue: {self.notification.title} -> {self.user.username} ({self.status})"


class NotificationSettings(models.Model):
    """Configuración global del sistema de notificaciones"""

    # Configuración general
    enable_async_processing = models.BooleanField(default=True, help_text="Habilitar procesamiento asíncrono")
    max_retries = models.IntegerField(default=3, help_text="Máximo número de reintentos")
    cleanup_days = models.IntegerField(default=30, help_text="Días para mantener notificaciones")

    # Configuración de email
    email_batch_size = models.IntegerField(default=50, help_text="Tamaño del lote para emails masivos")
    email_rate_limit = models.IntegerField(default=100, help_text="Límite de emails por hora")

    # Configuración de SMS
    sms_provider = models.CharField(max_length=50, blank=True, help_text="Proveedor de SMS")
    sms_api_key = models.CharField(max_length=255, blank=True, help_text="API Key para SMS")
    sms_rate_limit = models.IntegerField(default=20, help_text="Límite de SMS por hora")

    # Configuración de Slack
    slack_webhook_url = models.URLField(blank=True, help_text="URL del webhook de Slack")
    slack_default_channel = models.CharField(max_length=100, default='#alerts', help_text="Canal por defecto")

    # Configuración de Teams
    teams_webhook_url = models.URLField(blank=True, help_text="URL del webhook de Teams")

    # Configuración de webhooks
    webhook_timeout = models.IntegerField(default=30, help_text="Timeout para webhooks (segundos)")
    webhook_retries = models.IntegerField(default=2, help_text="Reintentos para webhooks")

    # Configuración de push notifications
    push_enabled = models.BooleanField(default=False, help_text="Habilitar notificaciones push")
    push_vapid_key = models.TextField(blank=True, help_text="Clave VAPID para push notifications")

    # Configuración de limpieza
    auto_cleanup = models.BooleanField(default=True, help_text="Limpieza automática habilitada")
    cleanup_frequency = models.CharField(max_length=20, default='daily',
                                       choices=[('hourly', 'Cada hora'), ('daily', 'Diario'), ('weekly', 'Semanal')])

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Configuración de Notificaciones'
        verbose_name_plural = 'Configuraciones de Notificaciones'

    def __str__(self):
        return "Configuración Global de Notificaciones"


class NotificationLog(models.Model):
    """Log detallado de todas las notificaciones enviadas"""

    notification = models.ForeignKey(Notification, on_delete=models.CASCADE)
    channel = models.ForeignKey(NotificationChannel, on_delete=models.CASCADE, null=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    status = models.CharField(max_length=20, choices=NotificationQueue.STATUS_CHOICES)
    channel_type = models.CharField(max_length=20)

    # Información de envío
    sent_at = models.DateTimeField(null=True, blank=True)
    delivery_time = models.FloatField(null=True, blank=True, help_text="Tiempo de entrega en segundos")

    # Información de error
    error_message = models.TextField(blank=True)
    error_code = models.CharField(max_length=50, blank=True)

    # Metadatos adicionales
    metadata = models.JSONField(default=dict)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'Log de Notificación'
        verbose_name_plural = 'Logs de Notificaciones'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'channel_type']),
            models.Index(fields=['sent_at']),
        ]

    def __str__(self):
        return f"Log: {self.notification.title} - {self.status}"


class UserPermission(models.Model):
    """Modelo para permisos personalizados de usuarios"""
    PERMISSION_TYPES = [
        ('CAN_LOGIN', 'Puede Autenticarse'),
        ('VIEW_REPORTES', 'Ver Reportes'),
        ('CREATE_REPORTES', 'Crear Reportes'),
        ('EDIT_REPORTES', 'Editar Reportes'),
        ('DELETE_REPORTES', 'Eliminar Reportes'),
        ('VIEW_INCIDENTES', 'Ver Incidentes'),
        ('CREATE_INCIDENTES', 'Crear Incidentes'),
        ('EDIT_INCIDENTES', 'Editar Incidentes'),
        ('DELETE_INCIDENTES', 'Eliminar Incidentes'),
        ('VIEW_USERS', 'Ver Usuarios'),
        ('CREATE_USERS', 'Crear Usuarios'),
        ('EDIT_USERS', 'Editar Usuarios'),
        ('DELETE_USERS', 'Eliminar Usuarios'),
        ('VIEW_LOGS', 'Ver Logs'),
        ('VIEW_NOTIFICATIONS', 'Ver Notificaciones'),
        ('MANAGE_PERMISSIONS', 'Gestionar Permisos'),
        ('VIEW_DASHBOARD', 'Ver Dashboard'),
        ('EXPORT_DATA', 'Exportar Datos'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='custom_permissions')
    permission_type = models.CharField(max_length=50, choices=PERMISSION_TYPES)
    granted = models.BooleanField(default=False)
    granted_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='granted_permissions')
    granted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['user', 'permission_type']
        verbose_name = 'Permiso de Usuario'
        verbose_name_plural = 'Permisos de Usuarios'

    def __str__(self):
        return f"{self.user.username} - {self.get_permission_type_display()}"


class UserApprovalRequest(models.Model):
    """Modelo para solicitudes de aprobación de usuarios"""
    STATUS_CHOICES = [
        ('PENDING', 'Pendiente'),
        ('APPROVED', 'Aprobado'),
        ('REJECTED', 'Rechazado'),
    ]

    requested_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_requests')
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField()
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    password = models.CharField(max_length=128)  # Hash de la contraseña
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_users')
    approved_at = models.DateTimeField(null=True, blank=True)
    rejection_reason = models.TextField(blank=True)
    details = models.JSONField(default=dict, blank=True)  # Para almacenar permisos solicitados
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Solicitud de Usuario'
        verbose_name_plural = 'Solicitudes de Usuarios'

    def __str__(self):
        return f"Solicitud de {self.username} - {self.get_status_display()}"

    def approve(self, approved_by):
        """Aprobar la solicitud de usuario"""
        from django.contrib.auth.hashers import make_password

        # Crear el usuario sin rehashear la contraseña (ya viene hasheada en self.password)
        user = User.objects.create(
            username=self.username,
            email=self.email,
            first_name=self.first_name,
            last_name=self.last_name,
            is_staff=self.is_staff,
            is_superuser=self.is_superuser,
            is_active=True,
        )
        # Asignar hash directamente
        user.password = self.password
        user.save(update_fields=['password'])

        # Actualizar la solicitud
        self.status = 'APPROVED'
        self.approved_by = approved_by
        self.approved_at = timezone.now()
        self.save()

        return user

    def reject(self, rejected_by, reason=""):
        """Rechazar la solicitud de usuario"""
        self.status = 'REJECTED'
        self.approved_by = rejected_by
        self.approved_at = timezone.now()
        self.rejection_reason = reason
        self.save()


class NotificationPreference(models.Model):
    """Modelo para preferencias de notificaciones de usuarios"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='notification_preferences')

    # Tipos de notificaciones que el usuario quiere recibir
    user_creation_notifications = models.BooleanField(default=True)
    user_approval_notifications = models.BooleanField(default=True)
    critical_operation_notifications = models.BooleanField(default=True)
    system_alert_notifications = models.BooleanField(default=True)
    data_change_notifications = models.BooleanField(default=False)
    security_event_notifications = models.BooleanField(default=True)
    backup_notifications = models.BooleanField(default=False)
    maintenance_notifications = models.BooleanField(default=True)

    # Configuración de notificaciones
    email_notifications = models.BooleanField(default=True)
    browser_notifications = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Preferencia de Notificación'
        verbose_name_plural = 'Preferencias de Notificaciones'

    def __str__(self):
        return f"Preferencias de {self.user.username}"


# ==================== CONFIGURACIÓN DE CORREO ====================

class EmailConfiguration(models.Model):
    """Configuración del servidor de correo para alertas del sistema"""

    name = models.CharField(max_length=100, unique=True, help_text="Nombre de la configuración")
    smtp_server = models.CharField(max_length=255, help_text="Servidor SMTP")
    smtp_port = models.IntegerField(default=587, help_text="Puerto SMTP")
    use_tls = models.BooleanField(default=True, help_text="Usar TLS")
    use_ssl = models.BooleanField(default=False, help_text="Usar SSL")
    username = models.CharField(max_length=255, help_text="Usuario del servidor SMTP")
    password = models.CharField(max_length=255, help_text="Contraseña del servidor SMTP")
    from_email = models.EmailField(help_text="Email remitente")
    from_name = models.CharField(max_length=255, default="VANT-SIEM", help_text="Nombre del remitente")

    is_active = models.BooleanField(default=True, help_text="Configuración activa")
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='email_configs')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Configuración de Correo'
        verbose_name_plural = 'Configuraciones de Correo'
        ordering = ['-is_active', '-created_at']

    def __str__(self):
        return f"{self.name} ({'Activa' if self.is_active else 'Inactiva'})"


# ==================== ALERTAS POR CORREO ====================

class EmailAlert(models.Model):
    """Configuración de alertas por correo para usuarios específicos"""

    ALERT_TYPES = [
        ('USER_CREATE_REQUEST', 'Solicitud de Creación de Usuario'),
        ('USER_APPROVED', 'Usuario Aprobado'),
        ('USER_REJECTED', 'Usuario Rechazado'),
        ('INCIDENT_CREATED', 'Incidente Creado'),
        ('INCIDENT_UPDATED', 'Incidente Actualizado'),
        ('REPORT_CREATED', 'Reporte Creado'),
        ('REPORT_UPDATED', 'Reporte Actualizado'),
        ('SECURITY_EVENT', 'Evento de Seguridad'),
        ('SYSTEM_ERROR', 'Error del Sistema'),
        ('BACKUP_COMPLETED', 'Respaldo Completado'),
        ('BACKUP_FAILED', 'Respaldo Fallido'),
        ('MAINTENANCE_SCHEDULED', 'Mantenimiento Programado'),
        ('LOGIN_FAILED', 'Intento de Login Fallido'),
        ('PERMISSION_CHANGED', 'Permisos Modificados'),
    ]

    PRIORITY_CHOICES = [
        ('LOW', 'Baja'),
        ('MEDIUM', 'Media'),
        ('HIGH', 'Alta'),
        ('CRITICAL', 'Crítica'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='email_alerts')
    alert_type = models.CharField(max_length=50, choices=ALERT_TYPES)
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default='MEDIUM')
    enabled = models.BooleanField(default=True, help_text="Alerta habilitada")

    # Configuración específica de la alerta
    subject_template = models.CharField(max_length=255, blank=True, help_text="Plantilla del asunto")
    body_template = models.TextField(blank=True, help_text="Plantilla del cuerpo del correo")

    # Condiciones para envío
    send_immediately = models.BooleanField(default=True, help_text="Enviar inmediatamente")
    send_daily_summary = models.BooleanField(default=False, help_text="Incluir en resumen diario")
    send_weekly_summary = models.BooleanField(default=False, help_text="Incluir en resumen semanal")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Alerta por Correo'
        verbose_name_plural = 'Alertas por Correo'
        unique_together = ['user', 'alert_type']
        ordering = ['user__username', 'alert_type']

    def __str__(self):
        return f"{self.user.username} - {self.get_alert_type_display()}"


# ==================== HISTORIAL DE CORREOS ENVIADOS ====================

class EmailLog(models.Model):
    """Registro de correos enviados por el sistema"""

    STATUS_CHOICES = [
        ('PENDING', 'Pendiente'),
        ('SENT', 'Enviado'),
        ('FAILED', 'Fallido'),
        ('BOUNCED', 'Rebotado'),
    ]

    to_email = models.EmailField()
    to_user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    subject = models.CharField(max_length=255)
    alert_type = models.CharField(max_length=50, choices=EmailAlert.ALERT_TYPES)
    priority = models.CharField(max_length=20, choices=EmailAlert.PRIORITY_CHOICES)

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    error_message = models.TextField(blank=True, help_text="Mensaje de error si falló el envío")

    sent_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'Log de Correo'
        verbose_name_plural = 'Logs de Correos'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.to_email} - {self.subject} ({self.get_status_display()})"


class AnalysisAPIConfig(models.Model):
    """Configuración de API para servicios de análisis (VirusTotal, AbuseIPDB, MacVendors)."""
    virustotal_api_key = models.CharField(max_length=1024, blank=True, default="")
    abuseipdb_api_key = models.CharField(max_length=1024, blank=True, default="")
    macvendors_api_key = models.CharField(max_length=1024, blank=True, default="")  # opcional
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='analysis_api_configs')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Configuración de APIs de Análisis'
        verbose_name_plural = 'Configuraciones de APIs de Análisis'

    def __str__(self):
        return f"APIs de Análisis ({'Activa' if self.is_active else 'Inactiva'})"


# ==================== MODELOS PARA HISTÓRICO DE ANÁLISIS ====================

class AbuseIPDBAnalysisRecord(models.Model):
    """Registro histórico de análisis de IP con AbuseIPDB"""
    ip_address = models.GenericIPAddressField(db_index=True, help_text="Dirección IP analizada")
    status_code = models.IntegerField(help_text="Código de estado HTTP de la respuesta")
    result = models.JSONField(default=dict, help_text="Resultado completo de la API")
    requested_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='abuseipdb_analyses')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Análisis AbuseIPDB'
        verbose_name_plural = 'Análisis AbuseIPDB'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['ip_address', 'created_at']),
            models.Index(fields=['requested_by', 'created_at']),
        ]

    def __str__(self):
        return f"AbuseIPDB {self.ip_address} - {self.status_code}"


class VTAnalysisRecord(models.Model):
    """Registro histórico de análisis de indicadores con VirusTotal"""
    INDICATOR_TYPES = [
        ('domain', 'Dominio'),
        ('url', 'URL'),
        ('file', 'Archivo'),
        ('ip', 'Dirección IP'),
    ]

    indicator = models.CharField(max_length=2048, db_index=True, help_text="Indicador analizado")
    indicator_type = models.CharField(max_length=20, choices=INDICATOR_TYPES, db_index=True)
    status_code = models.IntegerField(help_text="Código de estado HTTP de la respuesta")
    result = models.JSONField(default=dict, help_text="Resultado completo de la API")
    requested_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='vt_analyses')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Análisis VirusTotal'
        verbose_name_plural = 'Análisis VirusTotal'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['indicator_type', 'created_at']),
            models.Index(fields=['requested_by', 'created_at']),
        ]

    def __str__(self):
        return f"VT {self.indicator_type} {self.indicator[:50]} - {self.status_code}"


class MacVendorsAnalysisRecord(models.Model):
    """Registro histórico de análisis de MAC con MacVendors"""
    mac_address = models.CharField(max_length=17, db_index=True, help_text="Dirección MAC analizada")
    vendor = models.CharField(max_length=255, blank=True, help_text="Fabricante identificado")
    status_code = models.IntegerField(help_text="Código de estado HTTP de la respuesta")
    result = models.JSONField(default=dict, help_text="Resultado completo de la API")
    requested_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='macvendors_analyses')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Análisis MacVendors'
        verbose_name_plural = 'Análisis MacVendors'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['mac_address', 'created_at']),
            models.Index(fields=['vendor', 'created_at']),
            models.Index(fields=['requested_by', 'created_at']),
        ]

    def __str__(self):
        return f"MacVendors {self.mac_address} - {self.vendor or 'Unknown'}"


# ==================== CONFIGURACIÓN DE OLLAMA (IA) ====================

class OllamaConfig(models.Model):
    """Configuración del servicio de IA Ollama"""

    # Configuración de conexión
    ollama_url = models.URLField(default="http://localhost:11434", help_text="URL del servidor Ollama")
    ollama_model = models.CharField(max_length=100, default="llama3.2", help_text="Modelo de IA a utilizar")

    # Parámetros de generación
    max_tokens = models.IntegerField(default=2000, help_text="Máximo número de tokens en respuestas")
    temperature = models.FloatField(default=0.3, help_text="Temperatura para generación (0.1-1.0)")
    timeout_seconds = models.IntegerField(default=30, help_text="Timeout en segundos para llamadas")

    # Estado del servicio
    is_active = models.BooleanField(default=True, help_text="Servicio de IA habilitado")

    # Permisos de acceso a datos
    can_read_snort_logs = models.BooleanField(default=True, help_text="Puede leer logs de Snort")
    can_read_suricata_logs = models.BooleanField(default=True, help_text="Puede leer logs de Suricata")
    can_read_incidents = models.BooleanField(default=True, help_text="Puede leer incidentes")
    can_read_reports = models.BooleanField(default=True, help_text="Puede leer reportes")
    can_read_users = models.BooleanField(default=False, help_text="Puede leer datos de usuarios")
    can_read_system_logs = models.BooleanField(default=False, help_text="Puede leer logs del sistema")

    # Permisos de tareas automáticas
    auto_generate_reports = models.BooleanField(default=False, help_text="Generar reportes automáticamente en alertas")
    auto_send_emails = models.BooleanField(default=False, help_text="Enviar emails automáticamente")
    auto_create_incidents = models.BooleanField(default=False, help_text="Crear incidentes automáticamente")

    # Configuración de alertas automáticas
    alert_threshold_critical = models.IntegerField(default=10, help_text="Umbral para alertas críticas")
    alert_threshold_high = models.IntegerField(default=50, help_text="Umbral para alertas altas")
    auto_report_interval_hours = models.IntegerField(default=24, help_text="Intervalo para reportes automáticos (horas)")

    # Metadatos
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Configuración de Ollama'
        verbose_name_plural = 'Configuraciones de Ollama'
        ordering = ['-updated_at']

    def __str__(self):
        return f"Ollama Config ({self.ollama_model}) - {'Activa' if self.is_active else 'Inactiva'}"

    @classmethod
    def get_active_config(cls):
        """Obtener la configuración activa actual"""
        try:
            return cls.objects.filter(is_active=True).first()
        except Exception as e:
            # Si hay error de columna (durante migraciones), devolver None
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Error obteniendo configuración Ollama activa: {e}")
            return None



# ===== MODELO PARA CONFIGURACION LDAP =====

class LDAPConfig(models.Model):
    """Modelo para configurar la autenticación LDAP"""
    
    AUTHENTICATION_TYPE_CHOICES = [
        ('simple', 'Simple'),
        ('kerberos', 'Kerberos'),
    ]
    
    SERVER_TYPE_CHOICES = [
        ('active_directory', 'Active Directory'),
        ('openldap', 'OpenLDAP'),
        ('other', 'Otro'),
    ]
    
    nombre = models.CharField(max_length=100, unique=True, help_text="Nombre identificador de la configuración")
    servidor = models.CharField(max_length=255, help_text="Dirección del servidor LDAP (ej: ldap://servidor.dominio.com)")
    puerto = models.IntegerField(default=389, help_text="Puerto del servidor LDAP")
    use_ssl = models.BooleanField(default=False, help_text="Usar SSL/TLS")
    use_starttls = models.BooleanField(default=False, help_text="Usar StartTLS")
    cert_path = models.CharField(max_length=500, blank=True, null=True, help_text="Ruta al certificado CA (opcional)")
    
    # Bind
    bind_dn = models.CharField(max_length=500, blank=True, null=True, help_text="DN del usuario para bind (ej: cn=admin,dc=ejemplo,dc=com)")
    bind_password = models.CharField(max_length=255, blank=True, null=True, help_text="Contraseña del usuario bind")
    
    # search
    user_search_base = models.CharField(max_length=500, help_text="Base de búsqueda de usuarios (ej: ou=users,dc=ejemplo,dc=com)")
    user_search_filter = models.CharField(max_length=500, default='(uid={username})', help_text="Filtro de búsqueda de usuarios")
    
    # Group mapping
    group_search_base = models.CharField(max_length=500, blank=True, null=True, help_text="Base de búsqueda de grupos")
    group_search_filter = models.CharField(max_length=500, default='(member={user_dn})', help_text="Filtro de búsqueda de grupos")
    
    # Atributos
    username_attr = models.CharField(max_length=100, default='uid', help_text="Atributo que contiene el nombre de usuario")
    first_name_attr = models.CharField(max_length=100, default='givenName', help_text="Atributo para nombre")
    last_name_attr = models.CharField(max_length=100, default='sn', help_text="Atributo para apellido")
    email_attr = models.CharField(max_length=100, default='mail', help_text="Atributo para email")
    
    # Comportamiento
    is_active = models.BooleanField(default=True, help_text="Habilitar autenticación LDAP")
    is_default = models.BooleanField(default=False, help_text="Usar como método de autenticación por defecto")
    auto_create_user = models.BooleanField(default=True, help_text="Crear usuario automáticamente si no existe")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "Configuración LDAP"
        verbose_name_plural = "Configuraciones LDAP"
        ordering = ['-is_default', 'nombre']
    
    def __str__(self):
        return f"{self.nombre} ({self.servidor})"
