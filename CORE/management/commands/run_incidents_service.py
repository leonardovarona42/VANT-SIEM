import os
from django.core.management.base import BaseCommand
from django.core.management import call_command


class Command(BaseCommand):
    help = 'Run the Incidents Service (standalone mode)'

    def add_arguments(self, parser):
        parser.add_argument('--host', default='0.0.0.0', help='Host to bind (default: 0.0.0.0)')
        parser.add_argument('--port', default=8001, type=int, help='Port to listen on (default: 8001)')
        parser.add_argument('--noreload', action='store_true', help='Disable auto-reloader')

    def handle(self, *args, **options):
        host = options['host']
        port = options['port']

        os.environ['VANT_SERVICE_NAME'] = 'incidents-service'
        os.environ['VANT_MICROSERVICE_CHILD'] = 'true'

        self.stdout.write(self.style.SUCCESS(f'Starting Incidents Service on {host}:{port}'))
        self.stdout.write(self.style.SUCCESS('Endpoints:'))
        self.stdout.write(f'  - GET  /eventos/api/health/           Health check')
        self.stdout.write(f'  - POST /eventos/api/incidents/        Create incident')
        self.stdout.write(f'  - GET  /eventos/api/incidents/        List incidents')
        self.stdout.write(f'  - GET  /eventos/api/incidents/<pk>/   Incident detail')
        self.stdout.write('')

        call_command('runserver', f'{host}:{port}', '--noreload')
