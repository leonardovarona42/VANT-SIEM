from django.core.management.base import BaseCommand
from django.utils import timezone
from ids_ingest.models import SuricataEveAlert, SuricataFlow, SuricataStats, SuricataSystemLog, SuricataLog
from datetime import timedelta
import random

class Command(BaseCommand):
    help = 'Populate test data for IDS models to test dashboard charts'

    def handle(self, *args, **options):
        self.stdout.write('Creating test IDS data...')

        # Create test EVE alerts
        self.create_eve_alerts()

        # Create test flows
        self.create_flows()

        # Create test stats
        self.create_stats()

        # Create test system logs
        self.create_system_logs()

        # Create test fast logs
        self.create_fast_logs()

        self.stdout.write(self.style.SUCCESS('Test IDS data created successfully!'))

    def create_eve_alerts(self):
        """Create test EVE alerts"""
        now = timezone.now()
        alerts_data = [
            {
                'timestamp': now - timedelta(hours=i),
                'event_type': 'alert',
                'src_ip': f'192.168.1.{random.randint(10, 250)}',
                'dest_ip': f'10.0.0.{random.randint(10, 250)}',
                'src_port': random.randint(1024, 65535),
                'dest_port': random.choice([80, 443, 22, 3389, 21]),
                'proto': random.choice(['TCP', 'UDP']),
                'signature_id': random.randint(1000000, 9999999),
                'signature_rev': 1,
                'category': random.choice(['Attempted Information Leak', 'Misc activity', 'Generic Protocol Command Decode']),
                'severity': random.choice([1, 2, 3]),
                'message': f'Suricata Alert {random.randint(1000, 9999)}',
                'raw_data': '{"event_type": "alert", "alert": {"signature_id": 12345}}'
            } for i in range(24)  # One per hour for timeline
        ]

        for data in alerts_data:
            alert = SuricataEveAlert(**data)
            alert.log_hash = alert.generate_hash()
            alert.save()

        self.stdout.write(f'Created {len(alerts_data)} EVE alerts')

    def create_flows(self):
        """Create test flows"""
        now = timezone.now()
        flows_data = [
            {
                'timestamp': now - timedelta(hours=i),
                'src_ip': f'192.168.1.{random.randint(10, 250)}',
                'dest_ip': f'10.0.0.{random.randint(10, 250)}',
                'src_port': random.randint(1024, 65535),
                'dest_port': random.choice([80, 443, 22, 3389, 21]),
                'proto': random.choice(['TCP', 'UDP']),
                'app_proto': random.choice(['http', 'tls', 'ssh', None]),
                'state': random.choice(['established', 'new', 'closed']),
                'pkts_toserver': random.randint(10, 1000),
                'pkts_toclient': random.randint(10, 1000),
                'bytes_toserver': random.randint(1000, 100000),
                'bytes_toclient': random.randint(1000, 100000),
                'start_time': now - timedelta(hours=i, minutes=random.randint(0, 59)),
                'end_time': now - timedelta(hours=i-1, minutes=random.randint(0, 59)),
                'age': random.randint(10, 3600),
                'raw_data': '{"event_type": "flow"}'
            } for i in range(12)  # Flows for last 12 hours
        ]

        for data in flows_data:
            flow = SuricataFlow(**data)
            flow.log_hash = flow.generate_hash()
            flow.save()

        self.stdout.write(f'Created {len(flows_data)} flows')

    def create_stats(self):
        """Create test stats"""
        now = timezone.now()
        stats_data = [
            {
                'timestamp': now - timedelta(hours=i),
                'uptime': 3600 + (i * 3600),  # Increasing uptime
                'total_packets': random.randint(10000, 100000),
                'total_bytes': random.randint(1000000, 10000000),
                'packets_per_second': random.uniform(10.5, 150.8),
                'bytes_per_second': random.uniform(1000.5, 50000.8),
                'total_flows': random.randint(100, 1000),
                'total_alerts': random.randint(5, 50),
                'total_drops': random.randint(0, 10),
                'memory_usage': random.uniform(45.5, 85.5),
                'cpu_usage': random.uniform(15.5, 65.5),
                'rules_loaded': 25000,
                'rules_failed': random.randint(0, 5),
                'raw_data': '{"event_type": "stats"}'
            } for i in range(6)  # Stats for last 6 hours
        ]

        for data in stats_data:
            stat = SuricataStats(**data)
            stat.log_hash = stat.generate_hash()
            stat.save()

        self.stdout.write(f'Created {len(stats_data)} stats records')

    def create_system_logs(self):
        """Create test system logs"""
        now = timezone.now()
        levels = ['INFO', 'WARNING', 'ERROR']
        components = ['detect', 'decode', 'output', 'flow', 'stream']
        messages = [
            'Engine started successfully',
            'Rule reload completed',
            'Memory usage warning',
            'Packet drop detected',
            'Interface monitoring active',
            'Signature update applied',
            'Configuration reloaded',
            'Thread pool optimized'
        ]

        system_logs_data = [
            {
                'timestamp': now - timedelta(hours=random.randint(0, 24)),
                'level': random.choice(levels),
                'component': random.choice(components),
                'message': random.choice(messages),
                'raw_line': f'[INFO] {random.choice(messages)}'
            } for _ in range(20)
        ]

        for data in system_logs_data:
            log = SuricataSystemLog(**data)
            log.log_hash = log.generate_hash()
            log.save()

        self.stdout.write(f'Created {len(system_logs_data)} system logs')

    def create_fast_logs(self):
        """Create test fast logs"""
        now = timezone.now()
        fast_logs_data = [
            {
                'timestamp': now - timedelta(hours=i),
                'severity': random.choice(['High', 'Medium', 'Low']),
                'priority': random.choice([1, 2, 3]),
                'src_ip': f'192.168.1.{random.randint(10, 250)}',
                'dst_ip': f'10.0.0.{random.randint(10, 250)}',
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443, 22, 3389, 21]),
                'protocol': random.choice(['TCP', 'UDP']),
                'message': f'Fast log alert {random.randint(1000, 9999)}',
                'gid': 1,
                'sid': random.randint(1000000, 9999999),
                'rev': 1,
                'classification': 'Misc activity',
                'raw': f'Fast log entry {random.randint(1000, 9999)}'
            } for i in range(8)  # Fast logs for last 8 hours
        ]

        for data in fast_logs_data:
            log = SuricataLog(**data)
            log.log_hash = log.generate_hash()
            log.save()

        self.stdout.write(f'Created {len(fast_logs_data)} fast logs')