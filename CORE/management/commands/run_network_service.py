import os
from django.core.management.base import BaseCommand
from django.core.management import call_command


class Command(BaseCommand):
    help = 'Run the Network Service (standalone mode)'

    def add_arguments(self, parser):
        parser.add_argument('--host', default='0.0.0.0', help='Host to bind (default: 0.0.0.0)')
        parser.add_argument('--port', default=8004, type=int, help='Port to listen on (default: 8004)')
        parser.add_argument('--noreload', action='store_true', help='Disable auto-reloader')

    def handle(self, *args, **options):
        host = options['host']
        port = options['port']

        os.environ['VANT_SERVICE_NAME'] = 'network-service'
        os.environ['VANT_MICROSERVICE_CHILD'] = 'true'

        self.stdout.write(self.style.SUCCESS(f'Starting Network Service on {host}:{port}'))
        self.stdout.write(self.style.SUCCESS('Endpoints:'))
        self.stdout.write(f'  - GET  /eventos/api/health/           Health check')
        self.stdout.write(f'  - GET  /eventos/api/redes/            List networks')
        self.stdout.write(f'  - GET  /eventos/api/red/<pk>/         Network detail')
        self.stdout.write(f'  - GET  /eventos/api/esquema/fisico/   Physical topology')
        self.stdout.write(f'  - GET  /eventos/api/esquema/logico/   Logical topology')
        self.stdout.write('')

        call_command('runserver', f'{host}:{port}', '--noreload')
