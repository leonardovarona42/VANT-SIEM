"""
Management command to run the Incidents Service
Isolated process with its own DB connection
"""
import os
import signal
import logging
import threading
from django.core.management.base import BaseCommand
from django.conf import settings

from CORE.service_bus import ServiceBus
from CORE.events import ASSET_DLP_INCIDENT, LOG_ALERT_TRIGGERED, AI_PREDICTION_CREATED
from CORE.handlers.incidents_service import on_dlp_incident, on_log_alert, on_ai_prediction

logger = logging.getLogger('vant-siem.incidents-service')


class Command(BaseCommand):
    help = 'Run the Incidents Service as an isolated process'

    def add_arguments(self, parser):
        parser.add_argument('--host', default='0.0.0.0', help='Host to bind')
        parser.add_argument('--port', type=int, default=8001, help='Port for HTTP API')

    def handle(self, *args, **options):
        os.environ['VANT_SERVICE_NAME'] = 'incidents-service'

        self.stdout.write(self.style.SUCCESS('Starting Incidents Service...'))

        bus = ServiceBus(settings.SERVICE_BUS_URL)

        bus.subscribe('asset.dlp', on_dlp_incident)
        bus.subscribe('log.alert', on_log_alert)
        bus.subscribe('ai.prediction', on_ai_prediction)

        bus.start_listening()

        self.stdout.write(self.style.SUCCESS('Incidents Service running. Listening for events.'))

        try:
            self._run_http_server(options['host'], options['port'])
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING('\nShutting down...'))
            bus.stop_listening()

    def _run_http_server(self, host, port):
        import threading
        from django.core.management import call_command
        call_command('runserver', f'{host}:{port}', '--noreload', use_ipv6=False)
