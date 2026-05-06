"""
Override Django's runserver to auto-start all available microservices.
Spawns each service as a subprocess on its designated port.
Services: Web Portal (8000), Incidents (8001), Assets (8002), Logs (9201)
"""
import os
import sys
import subprocess
import signal
import threading
import time
from django.conf import settings
from django.core.management.commands.runserver import Command as RunserverCommand

SERVICES = [
    {'name': 'Assets Service', 'command': 'run_assets_service', 'port': 8002, 'enabled': True},
    {'name': 'Logs Service', 'command': 'run_logs_service', 'port': 9201, 'enabled': True},
]


class Command(RunserverCommand):
    help = 'Run the development server with all microservices'

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument('--no-services', action='store_true', help='Skip starting microservices (default runserver only)')
        parser.add_argument('--services', nargs='*', help='Start only specified services (by name)')

    def handle(self, *args, **options):
        self.no_services = options.get('no_services', False)
        self.services_filter = options.get('services', None)

        service_name = os.environ.get('VANT_SERVICE_NAME', '')
        is_subprocess = os.environ.get('VANT_MICROSERVICE_CHILD', 'false') == 'true'

        if self.no_services or is_subprocess or service_name:
            if is_subprocess:
                pass
            else:
                self.stdout.write(self.style.WARNING(f'  Running standalone (no microservices). Use --services to enable.'))
                self.stdout.write('')
            super().handle(*args, **options)
            return

        self.stdout.write(self.style.SUCCESS('=' * 70))
        self.stdout.write(self.style.SUCCESS('  VANT-SIEM Platform - Starting All Microservices'))
        self.stdout.write(self.style.SUCCESS('=' * 70))
        self.stdout.write('')

        manage_py = os.path.join(settings.BASE_DIR, 'manage.py')
        python_exe = sys.executable

        self.processes = []

        for svc in SERVICES:
            if self.services_filter and svc['name'] not in self.services_filter:
                self.stdout.write(self.style.WARNING(f'  Skipping {svc["name"]} (not in filter)'))
                continue

            self._start_service(manage_py, python_exe, svc)

        self.stdout.write('')
        self.stdout.write(self.style.SUCCESS('-' * 70))
        self.stdout.write(self.style.SUCCESS(f'  All services started. Web Portal: http://{self.addr}:{self.port}'))
        self.stdout.write(self.style.SUCCESS('-' * 70))
        self.stdout.write('')
        self.stdout.write(self.style.WARNING('  Press Ctrl+C to stop all services'))
        self.stdout.write('')

        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

        try:
            super().handle(*args, **options)
        except KeyboardInterrupt:
            self._shutdown_services()

    def _start_service(self, manage_py, python_exe, svc):
        port = svc['port']
        env = os.environ.copy()
        env['DJANGO_SETTINGS_MODULE'] = settings.SETTINGS_MODULE
        env['VANT_MICROSERVICE_CHILD'] = 'true'
        env['VANT_SERVICE_NAME'] = svc['command'].replace('run_', '').replace('_service', '-service')

        self.stdout.write(f'  Starting {svc["name"]} on port {port}...', ending='')
        self.stdout.flush()

        try:
            proc = subprocess.Popen(
                [python_exe, manage_py, svc['command'], '--port', str(port), '--noreload'],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
            )
            self.processes.append({'name': svc['name'], 'port': port, 'process': proc})
            self.stdout.write(self.style.SUCCESS(f' OK (PID: {proc.pid})'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f' FAILED: {e}'))

    def _handle_shutdown(self, signum, frame):
        self.stdout.write('')
        self.stdout.write(self.style.WARNING('\n  Shutting down all services...'))
        self._shutdown_services()
        sys.exit(0)

    def _shutdown_services(self):
        for p in self.processes:
            try:
                proc = p['process']
                if proc.poll() is None:
                    self.stdout.write(f'  Stopping {p["name"]} (PID: {proc.pid})...', ending='')
                    self.stdout.flush()
                    if os.name == 'nt':
                        subprocess.call(['taskkill', '/F', '/PID', str(proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    else:
                        proc.terminate()
                    self.stdout.write(self.style.SUCCESS(' OK'))
            except Exception:
                pass
