import os
from django.core.management.base import BaseCommand
from django.core.management import call_command


class Command(BaseCommand):
    help = 'Run the OpenSearch Logs Service (standalone mode)'

    def add_arguments(self, parser):
        parser.add_argument('--host', default='0.0.0.0', help='Host to bind (default: 0.0.0.0)')
        parser.add_argument('--port', default=9201, type=int, help='Port to listen on (default: 9201)')
        parser.add_argument('--noreload', action='store_true', help='Disable auto-reloader')

    def handle(self, *args, **options):
        host = options['host']
        port = options['port']

        os.environ['VANT_SERVICE_NAME'] = 'logs-service'
        os.environ['VANT_MICROSERVICE_CHILD'] = 'true'

        self.stdout.write(self.style.SUCCESS(f'Starting OpenSearch Logs Service on {host}:{port}'))
        self.stdout.write(self.style.SUCCESS('Endpoints:'))
        self.stdout.write(f'  - GET  /logs/health/            Health check')
        self.stdout.write(f'  - POST /logs/api/ingest/        Single log ingestion')
        self.stdout.write(f'  - POST /logs/api/ingest/bulk/   Bulk log ingestion (up to 5000)')
        self.stdout.write(f'  - POST /logs/api/syslog/        Syslog receiver (HTTP)')
        self.stdout.write(f'  - GET  /logs/api/events/        List/search events')
        self.stdout.write(f'  - GET  /logs/api/events/<pk>/   Event detail')
        self.stdout.write(f'  - GET  /logs/api/statistics/    Statistics dashboard')
        self.stdout.write(f'  - CRUD /logs/sources/           Log source management')
        self.stdout.write(f'  - CRUD /logs/retention/         Retention policies')
        self.stdout.write('')
        self.stdout.write(self.style.WARNING('Supported source types:'))
        self.stdout.write('  - firewall_huawei (Huawei USG/eudemon)')
        self.stdout.write('  - snort, suricata (IDS/IPS)')
        self.stdout.write('  - windows_ad, windows_dhcp, windows_dns')
        self.stdout.write('  - samba (Linux file servers)')
        self.stdout.write('  - agent_filelog (VANT-Agent pushed logs)')
        self.stdout.write('  - generic_syslog (RFC 3164/5424)')
        self.stdout.write('')

        call_command('runserver', f'{host}:{port}', '--noreload')
