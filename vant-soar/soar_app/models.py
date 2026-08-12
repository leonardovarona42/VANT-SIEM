import logging
from django.db import models

logger = logging.getLogger(__name__)

RISK_CHOICES = [
    ("low", "Bajo"),
    ("medium", "Medio"),
    ("high", "Alto"),
    ("critical", "Critico"),
]

PREDICTION_MODE_CHOICES = [
    ("off", "Desactivado"),
    ("suggest", "Sugerir (no automatico)"),
    ("automatic", "Automatico (crea reportes)"),
]

MODEL_FRAMEWORK_CHOICES = [
    ("rules", "Reglas heuristicas"),
    ("sklearn", "Scikit-learn"),
    ("keras", "Keras / TensorFlow"),
    ("tflite", "TensorFlow Lite"),
]


class SoarConfig(models.Model):
    prediction_mode = models.CharField(
        max_length=16, choices=PREDICTION_MODE_CHOICES, default="suggest"
    )
    enabled = models.BooleanField(default=True)
    report_threshold = models.FloatField(
        default=0.6, help_text="Score minimo (0-1) para generar reporte/evento"
    )
    block_threshold = models.FloatField(
        default=0.85, help_text="Score minimo para severidad critica"
    )
    high_threshold = models.FloatField(
        default=0.7, help_text="Score minimo para severidad alta"
    )
    medium_threshold = models.FloatField(
        default=0.5, help_text="Score minimo para severidad media"
    )
    window_minutes = models.IntegerField(default=5, help_text="Ventana corta para bursts")
    burst_same_dst_threshold = models.IntegerField(
        default=20, help_text="Nº de conexiones/min al mismo destino = bot"
    )
    burst_targets_threshold = models.IntegerField(
        default=15, help_text="Nº de destinos internos distintos/min = scan"
    )
    report_informante = models.CharField(
        max_length=128, default="SOAR Automatico"
    )
    create_report_in_soc = models.BooleanField(default=True)
    auto_ack_after_days = models.IntegerField(default=7)
    last_cursor = models.BigIntegerField(default=0, help_text="Ultimo LogEventRaw.id procesado")
    last_run_at = models.DateTimeField(blank=True, null=True)
    events_processed = models.BigIntegerField(default=0)
    predictions_made = models.BigIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "soar_config"

    def __str__(self):
        return f"SOAR config ({self.get_prediction_mode_display()})"


def get_or_create_config() -> SoarConfig:
    cfg, _ = SoarConfig.objects.get_or_create(pk=1)
    return cfg


class ThreatPort(models.Model):
    port = models.IntegerField()
    protocol = models.CharField(max_length=16, default="tcp")
    name = models.CharField(max_length=128)
    description = models.TextField(blank=True, default="")
    severity = models.CharField(max_length=16, choices=RISK_CHOICES, default="high")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "soar_threat_ports"
        unique_together = [("port", "protocol")]
        ordering = ["port"]

    def __str__(self):
        return f":{self.port}/{self.protocol} {self.name}"


class CriticalPort(models.Model):
    port = models.IntegerField()
    service_name = models.CharField(max_length=64)
    severity = models.CharField(max_length=16, choices=RISK_CHOICES, default="critical")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "soar_critical_ports"
        unique_together = [("port", "service_name")]
        ordering = ["port"]

    def __str__(self):
        return f":{self.port} {self.service_name}"


class SoarModel(models.Model):
    name = models.CharField(
        max_length=64, help_text="Identificador del modelo (ip_reputation, incident_risk)"
    )
    framework = models.CharField(max_length=16, choices=MODEL_FRAMEWORK_CHOICES, default="rules")
    version = models.IntegerField(default=1)
    file_path = models.CharField(max_length=512, blank=True, default="")
    metrics = models.JSONField(default=dict, blank=True)
    trained_samples = models.IntegerField(default=0)
    feature_names = models.JSONField(default=list, blank=True)
    is_active = models.BooleanField(default=True)
    trained_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "soar_models"
        ordering = ["-trained_at"]

    def __str__(self):
        return f"{self.name} v{self.version} ({self.framework})"


class NetworkFeature(models.Model):
    ip = models.GenericIPAddressField(db_index=True)
    is_internal = models.BooleanField(default=False)
    window_start = models.DateTimeField(db_index=True)
    window_end = models.DateTimeField()
    conn_count = models.IntegerField(default=0)
    inbound_count = models.IntegerField(default=0)
    outbound_count = models.IntegerField(default=0)
    distinct_dst_ips = models.IntegerField(default=0)
    distinct_dst_ports = models.IntegerField(default=0)
    distinct_protos = models.IntegerField(default=0)
    critical_port_access = models.BooleanField(default=False)
    trojan_port_hit = models.BooleanField(default=False)
    burst_same_dst = models.IntegerField(default=0)
    burst_targets = models.IntegerField(default=0)
    internal_targets = models.IntegerField(default=0)
    external_targets = models.IntegerField(default=0)
    syn_count = models.IntegerField(default=0)
    abuse_score = models.IntegerField(default=0, help_text="AbuseIPDB confidence 0-100")
    geo_country = models.CharField(max_length=8, blank=True, default="")
    msg = models.CharField(max_length=512, blank=True, default="", help_text="Detalle del ataque/evento")
    score = models.FloatField(default=0, help_text="Score final 0-1")
    risk_level = models.CharField(max_length=16, choices=RISK_CHOICES, default="low")
    feature_vector = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "soar_network_features"
        ordering = ["-updated_at"]
        indexes = [
            models.Index(fields=["ip", "-window_start"]),
            models.Index(fields=["risk_level", "-updated_at"]),
        ]

    def __str__(self):
        return f"{self.ip} ({self.risk_level}, score={self.score:.2f})"


class SoarPrediction(models.Model):
    DECISION_CHOICES = [
        ("allow", "Permitir"),
        ("monitor", "Monitorear"),
        ("investigate", "Investigar"),
        ("block", "Bloquear"),
    ]
    STATUS_CHOICES = [
        ("new", "Nuevo"),
        ("acknowledged", "Reconocido"),
        ("confirmed", "Confirmado"),
        ("false_positive", "Falso positivo"),
    ]
    ip = models.GenericIPAddressField(db_index=True)
    score = models.FloatField()
    risk_level = models.CharField(max_length=16, choices=RISK_CHOICES)
    decision = models.CharField(max_length=16, choices=DECISION_CHOICES, default="monitor")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="new", db_index=True)
    model_version = models.IntegerField(default=0)
    model_framework = models.CharField(max_length=16, default="rules")
    features = models.JSONField(default=dict, blank=True)
    evidence = models.JSONField(default=list, blank=True, help_text="Reglas/razones que dispararon")
    bus_event_id = models.CharField(max_length=64, blank=True, default="")
    soc_report_id = models.CharField(max_length=64, blank=True, default="")
    playbook_run_id = models.CharField(max_length=64, blank=True, default="")
    source_event_ids = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    analyzed_at = models.DateTimeField(blank=True, null=True)
    feedback_note = models.TextField(blank=True, default="")

    class Meta:
        db_table = "soar_predictions"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["risk_level", "-created_at"]),
            models.Index(fields=["status", "-created_at"]),
        ]

    def __str__(self):
        return f"{self.ip} [{self.risk_level}] score={self.score:.2f} ({self.status})"


class FeedbackLabel(models.Model):
    LABEL_CHOICES = [
        ("confirmed", "Confirmado como amenaza"),
        ("false_positive", "Falso positivo"),
    ]
    prediction = models.ForeignKey(SoarPrediction, on_delete=models.CASCADE, related_name="feedback")
    label = models.CharField(max_length=20, choices=LABEL_CHOICES)
    notes = models.TextField(blank=True, default="")
    created_by = models.CharField(max_length=128, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "soar_feedback_labels"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.prediction.ip}: {self.label}"


class Playbook(models.Model):
    name = models.CharField(max_length=128)
    trigger_min_score = models.FloatField(default=0.6)
    trigger_risk_level = models.CharField(
        max_length=16, choices=RISK_CHOICES, default="high"
    )
    actions = models.JSONField(default=list, help_text="Lista de pasos: [{'type': ..., 'params': ...}]")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "soar_playbooks"
        ordering = ["name"]

    def __str__(self):
        return f"{self.name} (score>={self.trigger_min_score})"


class PlaybookRun(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pendiente"),
        ("running", "En ejecucion"),
        ("completed", "Completado"),
        ("failed", "Fallido"),
    ]
    playbook = models.ForeignKey(Playbook, on_delete=models.SET_NULL, null=True, related_name="runs")
    prediction = models.ForeignKey(SoarPrediction, on_delete=models.CASCADE, related_name="playbook_runs")
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default="pending")
    steps_log = models.JSONField(default=list, blank=True)
    error_message = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = "soar_playbook_runs"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.playbook} #{self.prediction_id} ({self.status})"
