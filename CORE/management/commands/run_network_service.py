"""
Management command to run the Network Management Service
Isolated process for IPAM, VLANs, subnets, network sites
"""
import os
import logging
from django.core.management.base import BaseCommand
from django.conf import settings

logger = logging.getLogger('vant-siem.network-service')


class Command(BaseCommand):
    help = 'Run the Network Management Service as an isolated process'

    def add_arguments(self, parser):
        parser.add_argument('--host', default='0.0.0.0', help='Host to bind')
        parser.add_argument('--port', type=int, default=8004, help='Port for HTTP API')

    def handle(self, *args, **options):
        os.environ['VANT_SERVICE_NAME'] = 'network-service'

        self.stdout.write(self.style.SUCCESS('Starting Network Management Service...'))
        self.stdout.write(self.style.SUCCESS(f'  API: http://{options["host"]}:{options["port"]}'))

        try:
            from django.core.management import call_command
            call_command('runserver', f'{options["host"]}:{options["port"]}', '--noreload', use_ipv6=False)
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING('\nShutting down...'))
