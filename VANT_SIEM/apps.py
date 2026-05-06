from django.apps import AppConfig


class VantSiemConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "VANT_SIEM"
    verbose_name = "VANT-SIEM Sistema de Gestion"

    def ready(self):
        from .logging_system import event_logger
        print("[START] VANT-SIEM: Sistema de logging inicializado automaticamente")
