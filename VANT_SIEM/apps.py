from django.apps import AppConfig


class VantSiemConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "VANT_SIEM"
    verbose_name = "VANT-SIEM Sistema de Gestion"

    def ready(self):
        """Inicializar el sistema cuando Django este listo"""
        # Importar aqui para evitar problemas de importacion circular
        from .logging_system import event_logger
        import VANT_SIEM.signals  # Importar senales para activarlas
        # El sistema de logging se inicia automaticamente
        # Solo se puede detener/iniciar desde la interfaz de superusuario
        print("[START] VANT-SIEM: Sistema de logging inicializado automaticamente")
        print("[START] VANT-SIEM: Senales de IA cargadas")
