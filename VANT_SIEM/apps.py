from django.apps import AppConfig

class VantSiemConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'VANT_SIEM'
    verbose_name = 'VANT-SIEM Sistema de Gestión'

    def ready(self):
        """Inicializar el sistema cuando Django esté listo"""
        # Importar aquí para evitar problemas de importación circular
        from .logging_system import event_logger
        import VANT_SIEM.signals  # Importar señales para activarlas

        # El sistema de logging se inicia automáticamente
        # Solo se puede detener/iniciar desde la interfaz de superusuario
        print("[START] VANT-SIEM: Sistema de logging inicializado automaticamente")
        print("[START] VANT-SIEM: Señales de IA cargadas")