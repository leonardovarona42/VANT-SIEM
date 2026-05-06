"""
Management command to run the Assets Service
Isolated process with its own DB connection
Handles: inventory, DLP policies, agent enrollment, heartbeat
"""
import os
import logging
from django.core.management.base import BaseCommand
from django.conf import settings

from CORE.service_bus import ServiceBus
from CORE.events import (
    ASSET_ENROLLED, ASSET_HEARTBEAT, ASSET_INVENTORY_UPDATED,
    ASSET_DLP_INCIDENT, ASSET_DLP_CONTAINED, ASSET_OFFLINE
)

logger = logging.getLogger('vant-siem.assets-service')


class Command(BaseCommand):
    help = 'Run the Assets Service as an isolated process'

    def add_arguments(self, parser):
        parser.add_argument('--host', default='0.0.0.0', help='Host to bind')
        parser.add_argument('--port', type=int, default=8002, help='Port for HTTP API')
        parser.add_argument('--noreload', action='store_true', help='Disable auto-reloader')

    def handle(self, *args, **options):
        os.environ['VANT_SERVICE_NAME'] = 'assets-service'

        self.stdout.write(self.style.SUCCESS('Starting Assets Service...'))

        bus = ServiceBus(settings.SERVICE_BUS_URL)
        bus.start_listening()

        self.stdout.write(self.style.SUCCESS('Assets Service running.'))
        self.stdout.write(self.style.SUCCESS(f'  API: http://{options["host"]}:{options["port"]}'))
        self.stdout.write(self.style.SUCCESS(f'  Events: {settings.SERVICE_BUS_URL}'))

        try:
            from django.core.management import call_command
            call_command('runserver', f'{options["host"]}:{options["port"]}', '--noreload', use_ipv6=False)
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING('\nShutting down...'))
            bus.stop_listening()
