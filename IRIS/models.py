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

    auto_analysis_enabled = models.BooleanField(default=False)
    analysis_interval_hours = models.IntegerField(default=24)
    anomaly_threshold = models.FloatField(default=0.1, help_text="Umbral para detección de anomalías (0-1)")
    min_confidence_score = models.FloatField(default=0.7, help_text="Confianza mínima para crear incidentes (0-1)")
    max_incidents_per_hour = models.IntegerField(default=10, help_text="Máximo incidentes por hora")
    require_human_approval = models.BooleanField(default=True, help_text="Requiere aprobación humana para medidas críticas")
    learning_enabled = models.BooleanField(default=True, help_text="Habilitar aprendizaje continuo")
    feedback_retrain_threshold = models.IntegerField(default=10, help_text="Feedback necesario para re-entrenar")

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
