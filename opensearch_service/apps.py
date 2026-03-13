import os
import sys

from django.apps import AppConfig
from django.db.models.signals import post_migrate


class OpenSearchServiceConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "opensearch_service"
    verbose_name = "OpenSearch Service"

    def ready(self):
        from .bootstrap import apply_opensearch_schema, start_opensearch_service

        # Aplicar schema OpenSearch al finalizar migraciones.
        post_migrate.connect(
            lambda **kwargs: apply_opensearch_schema(),
            dispatch_uid="opensearch_apply_schema",
        )

        # Autostart del servicio OpenSearch al ejecutar runserver.
        if "runserver" in sys.argv and os.environ.get("RUN_MAIN") == "true":
            start_opensearch_service()
