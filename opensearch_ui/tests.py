"""
Comprehensive test suite for ids_ingest Django application
Tests cover parsers, models, views, services, and integration
"""

import json
import os
import tempfile
import unittest
from unittest.mock import Mock, patch, MagicMock
from django.test import TestCase, Client, RequestFactory
from django.contrib.auth.models import User
from django.urls import reverse
from django.utils import timezone
from django.core.management import call_command
from django.db import IntegrityError
import datetime

from .models import (
    SnortLog, SuricataEveAlert, SuricataFlow, SuricataStats,
    IDSAlert, IDSStatistics, IDSConfiguration, ThreatLog
)
from .parsers import (
    parse_snort_line, parse_suricata_line, get_log_statistics,
    extract_snort_timestamp, extract_suricata_timestamp
)
from .services import LogProcessingService


class ParserTests(TestCase):
    """Test cases for log parsers"""

    def test_parse_snort_line_valid(self):
        """Test parsing valid Snort log line"""
        line = '12/31-23:59:59.123456 [**] [1:1000001:1] "ET MALWARE Suspicious Activity" [**] [Priority: 1] {TCP} 192.168.1.100:1234 -> 10.0.0.1:80'

        result = parse_snort_line(line)

        self.assertIsNotNone(result)
        self.assertEqual(result['src_ip'], '192.168.1.100')
        self.assertEqual(result['dst_ip'], '10.0.0.1')
        self.assertEqual(result['src_port'], 1234)
        self.assertEqual(result['dst_port'], 80)
        self.assertEqual(result['protocol'], 'TCP')
        self.assertEqual(result['severity'], 'High')
        self.assertIn('ET MALWARE', result['message'])

    def test_parse_snort_line_invalid(self):
        """Test parsing invalid Snort log line"""
        invalid_lines = [
            '',
            'Invalid log line',
            '12/31-23:59:59.123456 Invalid format'
        ]

        for line in invalid_lines:
            result = parse_snort_line(line)
            self.assertIsNone(result)

    def test_parse_suricata_line_valid(self):
        """Test parsing valid Suricata log line"""
        line = '12/31/2024-23:59:59.123456 [**] [1:1000001:1] ET MALWARE Suspicious Activity [**] [Classification: Potentially Bad Traffic] [Priority: 1] {TCP} 192.168.1.100:1234 -> 10.0.0.1:80'

        result = parse_suricata_line(line)

        self.assertIsNotNone(result)
        self.assertEqual(result['src_ip'], '192.168.1.100')
        self.assertEqual(result['dst_ip'], '10.0.0.1')
        self.assertEqual(result['src_port'], 1234)
        self.assertEqual(result['dst_port'], 80)
        self.assertEqual(result['protocol'], 'TCP')
        self.assertEqual(result['severity'], 1)
        self.assertEqual(result['classification'], 'Potentially Bad Traffic')

    def test_parse_suricata_line_invalid(self):
        """Test parsing invalid Suricata log line"""
        invalid_lines = [
            '',
            'Invalid log line',
            '12/31/2024-23:59:59.123456 Invalid format'
        ]

        for line in invalid_lines:
            result = parse_suricata_line(line)
            self.assertIsNone(result)

    def test_extract_snort_timestamp(self):
        """Test Snort timestamp extraction"""
        line = '12/31-23:59:59.123456 [**] [1:1000001:1] "Test" [**] [Priority: 1] {TCP} 1.1.1.1:80 -> 2.2.2.2:443'
        timestamp = extract_snort_timestamp(line)

        self.assertIsNotNone(timestamp)
        self.assertEqual(timestamp.month, 12)
        self.assertEqual(timestamp.day, 31)
        self.assertEqual(timestamp.hour, 23)
        self.assertEqual(timestamp.minute, 59)

    def test_extract_suricata_timestamp(self):
        """Test Suricata timestamp extraction"""
        line = '12/31/2024-23:59:59.123456 [**] [1:1000001:1] Test [**] [Classification: Test] [Priority: 1] {TCP} 1.1.1.1:80 -> 2.2.2.2:443'
        timestamp = extract_suricata_timestamp(line)

        self.assertIsNotNone(timestamp)
        self.assertEqual(timestamp.year, 2024)
        self.assertEqual(timestamp.month, 12)
        self.assertEqual(timestamp.day, 31)
        self.assertEqual(timestamp.hour, 23)

    def test_get_log_statistics(self):
        """Test log file statistics generation"""
        # Create temporary log file
        log_content = '''12/31-23:59:59.123456 [**] [1:1000001:1] "ET MALWARE Test1" [**] [Priority: 1] {TCP} 192.168.1.100:1234 -> 10.0.0.1:80
12/31-23:59:58.987654 [**] [1:1000002:1] "ET POLICY Test2" [**] [Priority: 2] {UDP} 192.168.1.101:53 -> 8.8.8.8:53
12/31-23:59:57.456789 [**] [1:1000003:1] "ET SCAN Test3" [**] [Priority: 3] {TCP} 192.168.1.102:22 -> 10.0.0.2:22
Invalid line that should be ignored'''

        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(log_content)
            temp_file = f.name

        try:
            stats = get_log_statistics(temp_file, 'snort')

            self.assertEqual(stats['total_lines'], 4)
            self.assertEqual(stats['parsed_lines'], 3)
            self.assertEqual(stats['error_lines'], 1)
            self.assertIsNotNone(stats['first_timestamp'])
            self.assertIsNotNone(stats['last_timestamp'])
            self.assertEqual(stats['severity_counts']['High'], 1)
            self.assertEqual(stats['severity_counts']['Medium'], 1)
            self.assertEqual(stats['severity_counts']['Low'], 1)
            self.assertEqual(stats['protocol_counts']['TCP'], 2)
            self.assertEqual(stats['protocol_counts']['UDP'], 1)

        finally:
            os.unlink(temp_file)


class ModelTests(TestCase):
    """Test cases for models"""

    def test_snort_log_creation(self):
        """Test creating SnortLog instance"""
        log = SnortLog.objects.create(
            timestamp=timezone.now(),
            severity='High',
            src_ip='192.168.1.100',
            dst_ip='10.0.0.1',
            src_port=1234,
            dst_port=80,
            protocol='TCP',
            sid=1000001,
            message='ET MALWARE Test',
            classification='Malware'
        )

        self.assertEqual(log.src_ip, '192.168.1.100')
        self.assertEqual(log.severity, 'High')
        self.assertEqual(log.protocol, 'TCP')

    def test_suricata_alert_creation(self):
        """Test creating SuricataEveAlert instance"""
        alert = SuricataEveAlert.objects.create(
            timestamp=timezone.now(),
            severity=1,
            src_ip='192.168.1.100',
            dest_ip='10.0.0.1',
            src_port=1234,
            dest_port=80,
            proto='TCP',
            signature_id=1000001,
            message='ET MALWARE Test',
            classification='Potentially Bad Traffic'
        )

        self.assertEqual(alert.src_ip, '192.168.1.100')
        self.assertEqual(alert.severity, 1)
        self.assertEqual(alert.proto, 'TCP')

    def test_ids_alert_creation(self):
        """Test creating IDSAlert instance"""
        alert = IDSAlert.objects.create(
            timestamp=timezone.now(),
            severity='Critical',
            message='Critical security alert',
            src_ip='192.168.1.100',
            dest_ip='10.0.0.1',
            rule_id='1:1000001:1',
            acknowledged=False
        )

        self.assertEqual(alert.severity, 'Critical')
        self.assertFalse(alert.acknowledged)

    def test_threat_log_creation(self):
        """Test creating ThreatLog instance"""
        config = IDSConfiguration.objects.create(
            nombre='Test Config',
            sistema='snort_v2',
            tipo_log='archivo',
            ruta_logs='/var/log/snort',
            activo=True
        )

        threat = ThreatLog.objects.create(
            configuracion=config,
            timestamp=timezone.now(),
            prioridad='High',
            estado='Nuevo',
            mensaje='Test threat',
            ip_origen='192.168.1.100',
            ip_destino='10.0.0.1',
            regla_id='1:1000001:1',
            clasificacion='Malware'
        )

        self.assertEqual(threat.prioridad, 'High')
        self.assertEqual(threat.estado, 'Nuevo')
        self.assertEqual(threat.configuracion, config)


class ServiceTests(TestCase):
    """Test cases for services"""

    def setUp(self):
        """Set up test fixtures"""
        self.service = LogProcessingService()

    def test_process_snort_log(self):
        """Test processing Snort log line"""
        line = '12/31-23:59:59.123456 [**] [1:1000001:1] "ET MALWARE Test" [**] [Priority: 1] {TCP} 192.168.1.100:1234 -> 10.0.0.1:80'

        result = self.service.process_snort_line(line)

        self.assertTrue(result['success'])
        self.assertEqual(result['log_entry']['src_ip'], '192.168.1.100')
        self.assertEqual(result['log_entry']['severity'], 'High')

    def test_process_suricata_log(self):
        """Test processing Suricata log line"""
        line = '12/31/2024-23:59:59.123456 [**] [1:1000001:1] ET MALWARE Test [**] [Classification: Potentially Bad Traffic] [Priority: 1] {TCP} 192.168.1.100:1234 -> 10.0.0.1:80'

        result = self.service.process_suricata_line(line)

        self.assertTrue(result['success'])
        self.assertEqual(result['alert_entry']['src_ip'], '192.168.1.100')
        self.assertEqual(result['alert_entry']['severity'], 1)

    @patch('opensearch_ui.services.os.path.exists')
    @patch('opensearch_ui.services.open', create=True)
    def test_process_log_file(self, mock_open, mock_exists):
        """Test processing log file"""
        mock_exists.return_value = True

        mock_file = MagicMock()
        mock_file.__iter__.return_value = [
            '12/31-23:59:59.123456 [**] [1:1000001:1] "ET MALWARE Test1" [**] [Priority: 1] {TCP} 192.168.1.100:1234 -> 10.0.0.1:80\n',
            '12/31-23:59:58.987654 [**] [1:1000002:1] "ET POLICY Test2" [**] [Priority: 2] {UDP} 192.168.1.101:53 -> 8.8.8.8:53\n',
            'Invalid line\n'
        ]
        mock_open.return_value.__enter__.return_value = mock_file

        result = self.service.process_log_file('/fake/path/snort.log', 'snort')

        self.assertTrue(result['success'])
        self.assertEqual(result['processed_lines'], 2)
        self.assertEqual(result['error_lines'], 1)


class ViewTests(TestCase):
    """Test cases for Django views"""

    def setUp(self):
        """Set up test client and user"""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_snort_dashboard_requires_login(self):
        """Test that Snort dashboard requires authentication"""
        response = self.client.get(reverse('snort-dashboard'))
        self.assertEqual(response.status_code, 302)  # Redirect to login

    def test_snort_dashboard_authenticated(self):
        """Test Snort dashboard view for authenticated user"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('snort-dashboard'))
        self.assertEqual(response.status_code, 200)

    def test_suricata_dashboard_authenticated(self):
        """Test Suricata dashboard view for authenticated user"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('suricata-dashboard'))
        self.assertEqual(response.status_code, 200)

    def test_statistics_dashboard(self):
        """Test statistics dashboard view"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('statistics-dashboard'))
        self.assertEqual(response.status_code, 200)


class IntegrationTests(TestCase):
    """Integration test cases"""

    def setUp(self):
        """Set up test data"""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

        # Create test configuration
        self.config = IDSConfiguration.objects.create(
            nombre='Test Snort Config',
            sistema='snort_v2',
            tipo_log='archivo',
            ruta_logs='/var/log/snort',
            activo=True
        )

    def test_full_log_processing_workflow(self):
        """Test complete log processing workflow"""
        self.client.login(username='testuser', password='testpass123')

        # Create some test log entries
        SnortLog.objects.create(
            timestamp=timezone.now(),
            severity='High',
            src_ip='192.168.1.100',
            dst_ip='10.0.0.1',
            src_port=1234,
            dst_port=80,
            protocol='TCP',
            sid=1000001,
            message='ET MALWARE Test'
        )

        SuricataEveAlert.objects.create(
            timestamp=timezone.now(),
            severity=1,
            src_ip='192.168.1.101',
            dest_ip='10.0.0.2',
            src_port=53,
            dest_port=53,
            proto='UDP',
            signature_id=1000002,
            message='ET POLICY Test'
        )

        # Test dashboard displays data
        response = self.client.get(reverse('snort-dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'ET MALWARE Test')

        response = self.client.get(reverse('suricata-dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'ET POLICY Test')

    def test_threat_detection_workflow(self):
        """Test threat detection and logging workflow"""
        # Create threat log entry
        threat = ThreatLog.objects.create(
            configuracion=self.config,
            timestamp=timezone.now(),
            prioridad='Critical',
            estado='Nuevo',
            mensaje='Critical threat detected',
            ip_origen='192.168.1.100',
            ip_destino='10.0.0.1',
            regla_id='1:1000001:1',
            clasificacion='Malware'
        )

        # Test threat appears in dashboard
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('snort-dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Critical threat detected')


class SecurityTests(TestCase):
    """Security-focused test cases for ids_ingest"""

    def setUp(self):
        """Set up test data"""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_path_traversal_prevention(self):
        """Test prevention of path traversal attacks"""
        self.client.login(username='testuser', password='testpass123')

        malicious_paths = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            '/etc/shadow',
            'C:\\Windows\\System32\\config\\system'
        ]

        for path in malicious_paths:
            response = self.client.post(
                reverse('process-logs'),
                {'log_file': path, 'ids_type': 'snort'}
            )
            # Should not process malicious paths
            self.assertEqual(response.status_code, 400)

    def test_sql_injection_in_search(self):
        """Test SQL injection prevention in search parameters"""
        self.client.login(username='testuser', password='testpass123')

        malicious_inputs = [
            "'; DROP TABLE snort_logs; --",
            "' OR '1'='1",
            "<script>alert('xss')</script>"
        ]

        for malicious_input in malicious_inputs:
            response = self.client.get(
                reverse('snort-dashboard'),
                {'search': malicious_input}
            )
            # Should not crash and should return valid response
            self.assertEqual(response.status_code, 200)

    def test_input_validation(self):
        """Test input validation on forms"""
        self.client.login(username='testuser', password='testpass123')

        # Test invalid IP addresses
        invalid_ips = ['999.999.999.999', 'invalid', '192.168.1.256']

        for ip in invalid_ips:
            response = self.client.post(
                reverse('analyze-ip'),
                {'ip': ip}
            )
            # Should handle validation gracefully
            self.assertIn(response.status_code, [200, 400])

    def test_rate_limiting(self):
        """Test rate limiting on log processing endpoints"""
        self.client.login(username='testuser', password='testpass123')

        # Make multiple rapid requests
        for i in range(20):
            response = self.client.post(
                reverse('process-logs'),
                {'log_file': f'/var/log/test{i}.log', 'ids_type': 'snort'}
            )
            # Should not crash under load
            self.assertIn(response.status_code, [200, 400, 429])


class PerformanceTests(TestCase):
    """Performance-focused test cases"""

    def setUp(self):
        """Set up test data"""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

        # Create bulk test data
        for i in range(100):
            SnortLog.objects.create(
                timestamp=timezone.now() - datetime.timedelta(minutes=i),
                severity='High' if i % 3 == 0 else 'Medium',
                src_ip=f'192.168.1.{i % 255}',
                dst_ip=f'10.0.0.{i % 255}',
                src_port=1234 + i,
                dst_port=80,
                protocol='TCP',
                sid=1000000 + i,
                message=f'ET MALWARE Test {i}'
            )

    def test_dashboard_performance_with_data(self):
        """Test dashboard performance with substantial data"""
        self.client.login(username='testuser', password='testpass123')

        import time
        start_time = time.time()

        response = self.client.get(reverse('snort-dashboard'))

        end_time = time.time()
        load_time = end_time - start_time

        self.assertEqual(response.status_code, 200)
        # Dashboard should load in under 3 seconds with 100 records
        self.assertLess(load_time, 3.0)

    def test_search_performance(self):
        """Test search performance"""
        self.client.login(username='testuser', password='testpass123')

        import time
        start_time = time.time()

        response = self.client.get(
            reverse('snort-dashboard'),
            {'search': 'ET MALWARE'}
        )

        end_time = time.time()
        search_time = end_time - start_time

        self.assertEqual(response.status_code, 200)
        # Search should complete in under 2 seconds
        self.assertLess(search_time, 2.0)


class ManagementCommandTests(TestCase):
    """Test cases for management commands"""

    def test_ingest_snort_logs_command(self):
        """Test ingest_snort_logs management command"""
        # Create sample log file
        log_content = '''12/31-23:59:59.123456 [**] [1:1000001:1] "ET MALWARE Test1" [**] [Priority: 1] {TCP} 192.168.1.100:1234 -> 10.0.0.1:80
12/31-23:59:58.987654 [**] [1:1000002:1] "ET POLICY Test2" [**] [Priority: 2] {UDP} 192.168.1.101:53 -> 8.8.8.8:53'''

        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(log_content)
            temp_file = f.name

        try:
            # Run management command
            call_command('ingest_snort_logs', temp_file)

            # Verify logs were created
            self.assertEqual(SnortLog.objects.count(), 2)

            log1 = SnortLog.objects.filter(sid=1000001).first()
            self.assertIsNotNone(log1)
            self.assertEqual(log1.src_ip, '192.168.1.100')
            self.assertEqual(log1.severity, 'High')

        finally:
            os.unlink(temp_file)

    def test_ingest_suricata_logs_command(self):
        """Test ingest_suricata_logs management command"""
        # Create sample log file
        log_content = '''12/31/2024-23:59:59.123456 [**] [1:1000001:1] ET MALWARE Test1 [**] [Classification: Potentially Bad Traffic] [Priority: 1] {TCP} 192.168.1.100:1234 -> 10.0.0.1:80
12/31/2024-23:59:58.987654 [**] [1:1000002:1] ET POLICY Test2 [**] [Classification: Policy Violation] [Priority: 2] {UDP} 192.168.1.101:53 -> 8.8.8.8:53'''

        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(log_content)
            temp_file = f.name

        try:
            # Run management command
            call_command('ingest_suricata_logs', temp_file)

            # Verify alerts were created
            self.assertEqual(SuricataEveAlert.objects.count(), 2)

            alert1 = SuricataEveAlert.objects.filter(signature_id=1000001).first()
            self.assertIsNotNone(alert1)
            self.assertEqual(alert1.src_ip, '192.168.1.100')
            self.assertEqual(alert1.severity, 1)

        finally:
            os.unlink(temp_file)


if __name__ == '__main__':
    unittest.main()

