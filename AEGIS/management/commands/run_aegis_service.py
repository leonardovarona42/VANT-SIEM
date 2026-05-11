import os
import logging
from django.core.management.base import BaseCommand
from django.core.management import call_command

from CORE.arkangel import ServiceBus

logger = logging.getLogger('vant-siem.aegis-service')

SERVICE_BUS_URL = 'redis://localhost:6379/10'


class Command(BaseCommand):
    help = 'Run the AEGIS DLP Service as an isolated process'

    def add_arguments(self, parser):
        parser.add_argument('--host', default='0.0.0.0', help='Host to bind')
        parser.add_argument('--port', type=int, default=8002, help='Port for HTTP API')
        parser.add_argument('--noreload', action='store_true', help='Disable auto-reloader')

    def handle(self, *args, **options):
        os.environ['VANT_SERVICE_NAME'] = 'aegis-service'
        os.environ['VANT_MICROSERVICE_CHILD'] = 'true'

        self.stdout.write(self.style.SUCCESS('Starting AEGIS DLP Service...'))

        bus = ServiceBus(SERVICE_BUS_URL)
        bus.start_listening()

        self.stdout.write(self.style.SUCCESS('AEGIS DLP Service running.'))
        self.stdout.write(self.style.SUCCESS(f'  API: http://{options["host"]}:{options["port"]}'))
        self.stdout.write(self.style.SUCCESS(f'  Events: {SERVICE_BUS_URL}'))

        try:
            call_command('runserver', f'{options["host"]}:{options["port"]}', '--noreload', use_ipv6=False)
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING('\nShutting down...'))
            bus.stop_listening()
