from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class AIModelConfig(models.Model):
    """Configuración de modelos de IA"""

    MODEL_TYPES = [
        ('anomaly_detector', 'Detector de Anomalías'),
        ('incident_classifier', 'Clasificador de Incidentes'),
        ('pattern_analyzer', 'Analizador de Patrones'),
    ]

    name = models.CharField(max_length=100, unique=True)
    model_type = models.CharField(max_length=20, choices=MODEL_TYPES)
    version = models.CharField(max_length=20)
    accuracy_score = models.FloatField(default=0.0)
    precision_score = models.FloatField(default=0.0)
    recall_score = models.FloatField(default=0.0)
    f1_score = models.FloatField(default=0.0)
    last_trained = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=False)
    model_path = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Configuración de Modelo IA"
        verbose_name_plural = "Configuraciones de Modelos IA"
        ordering = ['-updated_at']

    def __str__(self):
        return f"{self.name} v{self.version} ({self.get_model_type_display()})"

class AIPerformanceMetrics(models.Model):
    """Métricas de rendimiento del sistema de IA"""

    date = models.DateField(default=timezone.now)
    total_predictions = models.IntegerField(default=0)
    true_positives = models.IntegerField(default=0)
    false_positives = models.IntegerField(default=0)
    true_negatives = models.IntegerField(default=0)
    false_negatives = models.IntegerField(default=0)
    incidents_created = models.IntegerField(default=0)
    incidents_validated = models.IntegerField(default=0)
    average_response_time = models.FloatField(default=0.0)  # en segundos
    human_feedback_count = models.IntegerField(default=0)

    class Meta:
        verbose_name = "Métrica de Rendimiento IA"
        verbose_name_plural = "Métricas de Rendimiento IA"
        unique_together = ['date']
        ordering = ['-date']

    def __str__(self):
        return f"Métricas IA - {self.date}"

    @property
    def accuracy(self):
        if self.total_predictions == 0:
            return 0.0
        return (self.true_positives + self.true_negatives) / self.total_predictions

    @property
    def precision(self):
        total_positives = self.true_positives + self.false_positives
        if total_positives == 0:
            return 0.0
        return self.true_positives / total_positives

    @property
    def recall(self):
        total_actual_positives = self.true_positives + self.false_negatives
        if total_actual_positives == 0:
            return 0.0
        return self.true_positives / total_actual_positives

class HumanFeedback(models.Model):
    """Feedback humano para mejorar modelos de IA"""

    FEEDBACK_TYPES = [
        ('false_positive', 'Falso Positivo'),
        ('false_negative', 'Falso Negativo'),
        ('wrong_classification', 'Clasificación Incorrecta'),
        ('good_prediction', 'Predicción Correcta'),
    ]

    incident = models.ForeignKey('EVENT_M.Incidente', on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    feedback_type = models.CharField(max_length=20, choices=FEEDBACK_TYPES)
    correct_classification = models.CharField(max_length=100, blank=True, null=True)
    confidence_level = models.IntegerField(choices=[(i, f"{i}/10") for i in range(1, 11)], default=5)
    comments = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Feedback Humano"
        verbose_name_plural = "Feedback Humano"
        ordering = ['-created_at']

    def __str__(self):
        return f"Feedback {self.get_feedback_type_display()} - Incidente {self.incident.id}"

class AIAnalysisLog(models.Model):
    """Log de análisis realizados por IA"""

    ANALYSIS_TYPES = [
        ('anomaly_detection', 'Detección de Anomalías'),
        ('pattern_analysis', 'Análisis de Patrones'),
        ('incident_creation', 'Creación de Incidentes'),
        ('measure_application', 'Aplicación de Medidas'),
    ]

    analysis_type = models.CharField(max_length=20, choices=ANALYSIS_TYPES)
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    logs_analyzed = models.IntegerField(default=0)
    anomalies_detected = models.IntegerField(default=0)
    incidents_created = models.IntegerField(default=0)
    measures_applied = models.IntegerField(default=0)
    processing_time = models.FloatField(default=0.0)  # en segundos
    success = models.BooleanField(default=True)
    error_message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Log de Análisis IA"
        verbose_name_plural = "Logs de Análisis IA"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.get_analysis_type_display()} - {self.start_time.strftime('%Y-%m-%d %H:%M')}"

class AIConfiguration(models.Model):
    """Configuración general del sistema de IA"""

    # Adoption Phases
    ADOPTION_PHASES = [
        ('passive', 'Pasivo - Solo Predicciones'),
        ('supervised', 'Supervisado - Predicciones con Validación'),
        ('semi_automated', 'Semi-Automático - Incidentes de Alta Confianza'),
        ('full_automated', 'Totalmente Automático'),
    ]

    adoption_phase = models.CharField(
        max_length=20,
        choices=ADOPTION_PHASES,
        default='passive',
        help_text="Fase de adopción del sistema de IA"
    )

    # Core Settings
    auto_analysis_enabled = models.BooleanField(default=False)
    analysis_interval_hours = models.IntegerField(default=24)
    anomaly_threshold = models.FloatField(default=0.1, help_text="Umbral para detección de anomalías (0-1)")
    min_confidence_score = models.FloatField(default=0.7, help_text="Confianza mínima para crear incidentes (0-1)")

    # Rate Limiting and Safety Controls
    max_incidents_per_hour = models.IntegerField(default=10, help_text="Máximo incidentes por hora")
    max_predictions_per_hour = models.IntegerField(default=50, help_text="Máximo predicciones por hora")
    circuit_breaker_threshold = models.FloatField(default=0.3, help_text="Umbral de falsos positivos para activar circuit breaker (0-1)")
    circuit_breaker_enabled = models.BooleanField(default=True, help_text="Habilitar circuit breaker automático")

    # Approval and Automation Settings
    require_human_approval = models.BooleanField(default=True, help_text="Requiere aprobación humana para medidas críticas")
    auto_create_incidents = models.BooleanField(default=False, help_text="Crear incidentes automáticamente")
    auto_apply_measures = models.BooleanField(default=False, help_text="Aplicar medidas automáticamente")

    # Learning and Adaptation
    learning_enabled = models.BooleanField(default=True, help_text="Habilitar aprendizaje continuo")
    feedback_retrain_threshold = models.IntegerField(default=10, help_text="Feedback necesario para re-entrenar")
    adaptive_thresholds = models.BooleanField(default=True, help_text="Ajustar umbrales automáticamente basado en rendimiento")

    # Alerting and Monitoring
    enable_performance_alerts = models.BooleanField(default=True, help_text="Alertas de rendimiento del sistema")
    enable_anomaly_alerts = models.BooleanField(default=True, help_text="Alertas de anomalías detectadas")
    alert_email_recipients = models.JSONField(default=list, help_text="Lista de emails para alertas")

    # Advanced Features
    enable_deep_learning = models.BooleanField(default=False, help_text="Habilitar modelos de deep learning")
    enable_external_integrations = models.BooleanField(default=False, help_text="Integrar fuentes externas (EDR, firewalls)")
    correlation_time_window = models.IntegerField(default=30, help_text="Ventana de tiempo para correlación (minutos)")

    class Meta:
        verbose_name = "Configuración IA"
        verbose_name_plural = "Configuraciones IA"

    class Meta:
        verbose_name = "Configuración IA"
        verbose_name_plural = "Configuraciones IA"

    def __str__(self):
        return f"Configuración IA - {'Activado' if self.auto_analysis_enabled else 'Desactivado'}"

class IncidentPrediction(models.Model):
    """Predicciones de incidentes realizadas por IA"""

    PREDICTION_STATUS = [
        ('pending', 'Pendiente'),
        ('validated', 'Validado'),
        ('rejected', 'Rechazado'),
        ('auto_created', 'Creado Automáticamente'),
    ]

    incident_type = models.CharField(max_length=100)
    confidence_score = models.FloatField(default=0.0)
    severity_level = models.CharField(max_length=20, choices=[
        ('Low', 'Bajo'),
        ('Medium', 'Medio'),
        ('High', 'Alto'),
        ('Critical', 'Crítico'),
    ])
    description = models.TextField()
    involved_ips = models.JSONField(default=list)
    related_logs_count = models.IntegerField(default=0)
    status = models.CharField(max_length=20, choices=PREDICTION_STATUS, default='pending')
    created_incident = models.ForeignKey('EVENT_M.Incidente', on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    validated_at = models.DateTimeField(null=True, blank=True)
    validated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        verbose_name = "Predicción de Incidente"
        verbose_name_plural = "Predicciones de Incidentes"
        ordering = ['-created_at']

    def __str__(self):
        return f"Predicción: {self.incident_type} ({self.confidence_score:.2f})"

class AIRateLimit(models.Model):
    """Control de límites de tasa para acciones automatizadas"""

    ACTION_TYPES = [
        ('prediction_creation', 'Creación de Predicciones'),
        ('incident_creation', 'Creación de Incidentes'),
        ('measure_application', 'Aplicación de Medidas'),
        ('analysis_execution', 'Ejecución de Análisis'),
    ]

    action_type = models.CharField(max_length=25, choices=ACTION_TYPES)
    time_window_minutes = models.IntegerField(default=60)  # Ventana de tiempo en minutos
    max_actions = models.IntegerField(default=10)  # Máximo de acciones en la ventana
    current_count = models.IntegerField(default=0)
    window_start = models.DateTimeField(default=timezone.now)
    is_blocked = models.BooleanField(default=False)
    last_blocked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Límite de Tasa IA"
        verbose_name_plural = "Límites de Tasa IA"
        unique_together = ['action_type', 'time_window_minutes']

    def __str__(self):
        return f"{self.get_action_type_display()} - {self.current_count}/{self.max_actions} ({self.time_window_minutes}min)"

    def can_perform_action(self):
        """Verificar si se puede realizar la acción"""
        now = timezone.now()

        # Reset counter if time window has passed
        if (now - self.window_start).total_seconds() / 60 > self.time_window_minutes:
            self.current_count = 0
            self.window_start = now
            self.is_blocked = False
            self.save()

        return not self.is_blocked and self.current_count < self.max_actions

    def record_action(self):
        """Registrar una acción realizada"""
        if self.can_perform_action():
            self.current_count += 1
            if self.current_count >= self.max_actions:
                self.is_blocked = True
                self.last_blocked_at = timezone.now()
            self.save()
            return True
        return False

class AICircuitBreaker(models.Model):
    """Implementación del patrón Circuit Breaker para seguridad"""

    CIRCUIT_STATES = [
        ('closed', 'Cerrado - Funcionando Normal'),
        ('open', 'Abierto - Bloqueado por Fallos'),
        ('half_open', 'Semi-Abierto - Probando Recuperación'),
    ]

    name = models.CharField(max_length=100, unique=True)
    state = models.CharField(max_length=10, choices=CIRCUIT_STATES, default='closed')
    failure_threshold = models.IntegerField(default=5, help_text="Fallos consecutivos para abrir el circuito")
    recovery_timeout_seconds = models.IntegerField(default=300, help_text="Tiempo para intentar recuperación (segundos)")
    success_threshold = models.IntegerField(default=3, help_text="Éxitos consecutivos para cerrar el circuito")

    current_failures = models.IntegerField(default=0)
    current_successes = models.IntegerField(default=0)
    last_failure_time = models.DateTimeField(null=True, blank=True)
    last_success_time = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Circuit Breaker IA"
        verbose_name_plural = "Circuit Breakers IA"

    def __str__(self):
        return f"{self.name} - {self.get_state_display()}"

    def can_execute(self):
        """Verificar si se puede ejecutar la acción"""
        now = timezone.now()

        if self.state == 'open':
            # Check if recovery timeout has passed
            if self.last_failure_time and (now - self.last_failure_time).total_seconds() > self.recovery_timeout_seconds:
                self.state = 'half_open'
                self.current_successes = 0
                self.save()
                return True
            return False
        elif self.state == 'half_open':
            return True
        else:  # closed
            return True

    def record_success(self):
        """Registrar éxito"""
        now = timezone.now()
        self.last_success_time = now

        if self.state == 'half_open':
            self.current_successes += 1
            if self.current_successes >= self.success_threshold:
                self.state = 'closed'
                self.current_failures = 0
                self.current_successes = 0
        else:
            self.current_failures = 0

        self.save()

    def record_failure(self):
        """Registrar fallo"""
        now = timezone.now()
        self.last_failure_time = now
        self.current_failures += 1

        if self.current_failures >= self.failure_threshold:
            self.state = 'open'
            self.current_successes = 0

        self.save()

class AIAuditLog(models.Model):
    """Log de auditoría para todas las acciones automatizadas de IA"""

    ACTION_TYPES = [
        ('prediction_created', 'Predicción Creada'),
        ('prediction_validated', 'Predicción Validada'),
        ('prediction_rejected', 'Predicción Rechazada'),
        ('incident_auto_created', 'Incidente Creado Automáticamente'),
        ('measure_auto_applied', 'Medida Aplicada Automáticamente'),
        ('analysis_executed', 'Análisis Ejecutado'),
        ('model_trained', 'Modelo Entrenado'),
        ('rate_limit_exceeded', 'Límite de Tasa Excedido'),
        ('circuit_breaker_triggered', 'Circuit Breaker Activado'),
        ('human_feedback_received', 'Feedback Humano Recibido'),
    ]

    SEVERITY_LEVELS = [
        ('info', 'Información'),
        ('warning', 'Advertencia'),
        ('error', 'Error'),
        ('critical', 'Crítico'),
    ]

    action_type = models.CharField(max_length=25, choices=ACTION_TYPES)
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS, default='info')
    description = models.TextField()
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    related_incident = models.ForeignKey('EVENT_M.Incidente', on_delete=models.SET_NULL, null=True, blank=True)
    related_prediction = models.ForeignKey(IncidentPrediction, on_delete=models.SET_NULL, null=True, blank=True)
    metadata = models.JSONField(default=dict, help_text="Datos adicionales en formato JSON")
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Log de Auditoría IA"
        verbose_name_plural = "Logs de Auditoría IA"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['action_type', 'created_at']),
            models.Index(fields=['severity', 'created_at']),
            models.Index(fields=['user', 'created_at']),
        ]

    def __str__(self):
        return f"{self.get_action_type_display()} - {self.created_at.strftime('%Y-%m-%d %H:%M:%S')}"

class AIAlert(models.Model):
    """Sistema de alertas granular para diferentes tipos de eventos"""

    ALERT_TYPES = [
        ('performance_degraded', 'Rendimiento Degradado'),
        ('high_false_positive_rate', 'Alta Tasa de Falsos Positivos'),
        ('model_accuracy_drop', 'Caída en Precisión del Modelo'),
        ('rate_limit_exceeded', 'Límite de Tasa Excedido'),
        ('circuit_breaker_open', 'Circuit Breaker Abierto'),
        ('anomaly_detected', 'Anomalía Detectada'),
        ('incident_auto_created', 'Incidente Creado Automáticamente'),
        ('system_error', 'Error del Sistema'),
        ('training_completed', 'Entrenamiento Completado'),
        ('configuration_changed', 'Configuración Cambiada'),
    ]

    PRIORITY_LEVELS = [
        ('low', 'Baja'),
        ('medium', 'Media'),
        ('high', 'Alta'),
        ('critical', 'Crítica'),
    ]

    alert_type = models.CharField(max_length=25, choices=ALERT_TYPES)
    priority = models.CharField(max_length=10, choices=PRIORITY_LEVELS, default='medium')
    title = models.CharField(max_length=200)
    message = models.TextField()
    is_active = models.BooleanField(default=True)
    acknowledged = models.BooleanField(default=False)
    acknowledged_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Alerta IA"
        verbose_name_plural = "Alertas IA"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.get_alert_type_display()} - {self.title}"

    def acknowledge(self, user):
        """Marcar alerta como reconocida"""
        self.acknowledged = True
        self.acknowledged_by = user
        self.acknowledged_at = timezone.now()
        self.save()

    def resolve(self):
        """Marcar alerta como resuelta"""
        self.resolved = True
        self.resolved_at = timezone.now()
        self.save()
