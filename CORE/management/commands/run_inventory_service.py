import os
from django.core.management.base import BaseCommand
from django.core.management import call_command


class Command(BaseCommand):
    help = 'Run the Inventory Service (standalone mode)'

    def add_arguments(self, parser):
        parser.add_argument('--host', default='0.0.0.0', help='Host to bind (default: 0.0.0.0)')
        parser.add_argument('--port', default=8003, type=int, help='Port to listen on (default: 8003)')
        parser.add_argument('--noreload', action='store_true', help='Disable auto-reloader')

    def handle(self, *args, **options):
        host = options['host']
        port = options['port']

        os.environ['VANT_MICROSERVICE_CHILD'] = 'true'
        os.environ.setdefault('VANT_SERVICE_NAME', 'inventory-service')

        self.stdout.write(self.style.SUCCESS(f'Starting Inventory Service on {host}:{port}'))
        self.stdout.write(self.style.SUCCESS('Endpoints:'))
        self.stdout.write(f'  - GET  /inventory/api/health/        Health check')
        self.stdout.write(f'  - GET  /inventory/api/stats/         Dashboard statistics')
        self.stdout.write(f'  - POST /inventory/api/register/      Agent registration')
        self.stdout.write(f'  - POST /inventory/api/heartbeat/     Agent heartbeat')
        self.stdout.write(f'  - POST /inventory/api/inventory/submit/  Submit HW/SW inventory')
        self.stdout.write(f'  - POST /inventory/api/command-result/    Agent command result')
        self.stdout.write(f'  - GET  /inventory/api/agents/        List agents')
        self.stdout.write(f'  - GET  /inventory/api/software/      List software')
        self.stdout.write(f'  - POST /inventory/api/commands/      Queue command for agent')
        self.stdout.write('')

        call_command('runserver', f'{host}:{port}', '--noreload')
