from django.core.management.base import BaseCommand

from opensearch_service.bootstrap import is_autostart_enabled, set_autostart_enabled


class Command(BaseCommand):
    help = "Enable OpenSearch service autostart when running manage.py runserver."

    def handle(self, *args, **options):
        set_autostart_enabled(True)
        status = "enabled" if is_autostart_enabled() else "disabled"
        self.stdout.write(f"OpenSearch autostart is {status}.")
