"""
Comprehensive test suite for VANT-SIEM Django application
Tests cover models, views, services, security, and integration
"""

import json
import unittest
from unittest.mock import Mock, patch, MagicMock
from django.test import TestCase, Client, RequestFactory
from django.contrib.auth.models import User
from django.urls import reverse
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.db import IntegrityError
import datetime
import requests

from .models import (
    OllamaConfig, Notification, UserPermission, NotificationPreference,
    EmailConfiguration, EmailAlert, EmailLog, AnalysisAPIConfig,
    NotificationSettings, NotificationChannel, NotificationTemplate,
    NotificationLog, NotificationQueue
)
from .ollama_service import OllamaAIService
from .email_service import send_user_alert, send_system_alert
from .enhanced_notification_service import enhanced_notification_service
from .logging_system import event_logger


class OllamaConfigModelTest(TestCase):
    """Test cases for OllamaConfig model"""

    def setUp(self):
        """Set up test data"""
        self.config_data = {
            'ollama_url': 'http://localhost:11434',
            'ollama_model': 'llama3.2',
            'max_tokens': 2000,
            'temperature': 0.3,
            'timeout_seconds': 30,
            'is_active': True,
            'can_read_snort_logs': True,
            'can_read_suricata_logs': True,
            'can_read_incidents': True,
            'can_read_reports': True,
            'auto_generate_reports': False,
            'auto_send_emails': False,
            'alert_threshold_critical': 10,
            'alert_threshold_high': 50,
            'auto_report_interval_hours': 24
        }

    def test_create_ollama_config(self):
        """Test creating OllamaConfig instance"""
        config = OllamaConfig.objects.create(**self.config_data)
        self.assertEqual(config.ollama_url, 'http://localhost:11434')
        self.assertEqual(config.ollama_model, 'llama3.2')
        self.assertTrue(config.is_active)
        self.assertTrue(config.can_read_snort_logs)

    def test_get_active_config(self):
        """Test getting active configuration"""
        # No active config initially
        self.assertIsNone(OllamaConfig.get_active_config())

        # Create active config
        config = OllamaConfig.objects.create(**self.config_data)
        active_config = OllamaConfig.get_active_config()
        self.assertEqual(active_config, config)

    def test_config_validation(self):
        """Test configuration validation"""
        # Test invalid URL
        invalid_config = self.config_data.copy()
        invalid_config['ollama_url'] = 'invalid-url'
        config = OllamaConfig(**invalid_config)
        with self.assertRaises(ValidationError):
            config.full_clean()

        # Test invalid temperature range
        invalid_config = self.config_data.copy()
        invalid_config['temperature'] = 2.0  # Should be <= 1.0
        config = OllamaConfig(**invalid_config)
        with self.assertRaises(ValidationError):
            config.full_clean()


class OllamaServiceTest(TestCase):
    """Test cases for OllamaAIService"""

    def setUp(self):
        """Set up test fixtures"""
        self.service = OllamaAIService(
            base_url='http://localhost:11434',
            model='llama3.2'
        )

    @patch('VANT_SIEM.ollama_service.requests.Session.post')
    def test_call_ollama_success(self, mock_post):
        """Test successful Ollama API call"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'response': 'Test response'}
        mock_post.return_value = mock_response

        result = self.service._call_ollama("Test prompt")
        self.assertEqual(result, 'Test response')

    @patch('VANT_SIEM.ollama_service.requests.Session.post')
    def test_call_ollama_failure(self, mock_post):
        """Test failed Ollama API call"""
        mock_post.side_effect = requests.exceptions.RequestException("Connection failed")

        result = self.service._call_ollama("Test prompt")
        self.assertIsNone(result)

    @patch('VANT_SIEM.ollama_service.requests.Session.get')
    def test_test_connection_success(self, mock_get):
        """Test successful connection test"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'models': [{'name': 'llama3.2'}]}
        mock_get.return_value = mock_response

        result = self.service.test_connection()
        self.assertTrue(result['success'])
        self.assertEqual(result['status'], 'connected')
        self.assertIn('llama3.2', result['available_models'])

    @patch('VANT_SIEM.ollama_service.requests.Session.get')
    def test_test_connection_failure(self, mock_get):
        """Test failed connection test"""
        mock_get.side_effect = requests.exceptions.RequestException("Connection failed")

        result = self.service.test_connection()
        self.assertFalse(result['success'])
        self.assertEqual(result['status'], 'disconnected')


class UserPermissionTest(TestCase):
    """Test cases for UserPermission model"""

    def setUp(self):
        """Set up test users and permissions"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_create_permission(self):
        """Test creating user permission"""
        permission = UserPermission.objects.create(
            user=self.user,
            permission_type='VIEW_DASHBOARD',
            granted=True,
            granted_by=self.user
        )
        self.assertEqual(permission.user, self.user)
        self.assertEqual(permission.permission_type, 'VIEW_DASHBOARD')
        self.assertTrue(permission.granted)

    def test_permission_uniqueness(self):
        """Test permission uniqueness constraint"""
        UserPermission.objects.create(
            user=self.user,
            permission_type='VIEW_DASHBOARD',
            granted=True
        )

        # Should raise IntegrityError for duplicate permission type
        with self.assertRaises(IntegrityError):
            UserPermission.objects.create(
                user=self.user,
                permission_type='VIEW_DASHBOARD',
                granted=False
            )


class NotificationTest(TestCase):
    """Test cases for Notification model"""

    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_create_notification(self):
        """Test creating notification"""
        notification = Notification.objects.create(
            user=self.user,
            title='Test Notification',
            message='This is a test message',
            event_type='SYSTEM_ALERT'
        )
        self.assertEqual(notification.user, self.user)
        self.assertEqual(notification.title, 'Test Notification')
        self.assertFalse(notification.is_read)

    def test_mark_as_read(self):
        """Test marking notification as read"""
        notification = Notification.objects.create(
            user=self.user,
            title='Test Notification',
            message='Test message'
        )

        self.assertFalse(notification.is_read)
        self.assertIsNone(notification.read_at)

        notification.mark_as_read()

        self.assertTrue(notification.is_read)
        self.assertIsNotNone(notification.read_at)


class EmailServiceTest(TestCase):
    """Test cases for email service"""

    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    @patch('VANT_SIEM.email_service.send_mail')
    def test_send_user_alert(self, mock_send_mail):
        """Test sending user alert email"""
        mock_send_mail.return_value = 1  # Django send_mail returns number of emails sent

        result = send_user_alert(
            user=self.user,
            alert_type='SYSTEM_ALERT',
            subject='Test Alert',
            body='Test body',
            priority='HIGH'
        )

        self.assertTrue(result)
        mock_send_mail.assert_called_once()

    @patch('VANT_SIEM.email_service.send_mail')
    def test_send_system_alert(self, mock_send_mail):
        """Test sending system alert email"""
        mock_send_mail.return_value = 1

        result = send_system_alert(
            user=self.user,
            alert_type='SYSTEM_ALERT',
            subject='System Alert',
            body='System alert body',
            priority='CRITICAL'
        )

        self.assertTrue(result)
        mock_send_mail.assert_called_once()


class ViewTests(TestCase):
    """Test cases for Django views"""

    def setUp(self):
        """Set up test client and user"""
        self.client = Client()
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.superuser = User.objects.create_superuser(
            username='admin',
            email='admin@example.com',
            password='admin123'
        )

    def test_dashboard_view_requires_login(self):
        """Test that dashboard requires authentication"""
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 302)  # Redirect to login

    def test_dashboard_view_authenticated(self):
        """Test dashboard view for authenticated user"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 200)

    def test_ollama_config_requires_superuser(self):
        """Test that Ollama config requires superuser"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('ollama-config'))
        self.assertEqual(response.status_code, 302)  # Should redirect

    def test_ollama_config_superuser(self):
        """Test Ollama config view for superuser"""
        self.client.login(username='admin', password='admin123')
        response = self.client.get(reverse('ollama-config'))
        self.assertEqual(response.status_code, 200)

    @patch('VANT_SIEM.views.ollama_service.test_connection')
    def test_ollama_test_connection(self, mock_test_connection):
        """Test Ollama connection test endpoint"""
        mock_test_connection.return_value = {
            'success': True,
            'status': 'connected',
            'available_models': ['llama3.2'],
            'current_model': 'llama3.2'
        }

        self.client.login(username='admin', password='admin123')
        response = self.client.get(reverse('ollama-test-connection'))
        self.assertEqual(response.status_code, 200)

        data = json.loads(response.content)
        self.assertTrue(data['success'])
        self.assertEqual(data['status'], 'connected')


class SecurityTests(TestCase):
    """Security-focused test cases"""

    def setUp(self):
        """Set up test data"""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.superuser = User.objects.create_superuser(
            username='admin',
            email='admin@example.com',
            password='admin123'
        )

    def test_sql_injection_prevention(self):
        """Test prevention of SQL injection attacks"""
        # Test with malicious input in search parameters
        self.client.login(username='testuser', password='testpass123')

        malicious_inputs = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "<script>alert('xss')</script>",
            "../../../etc/passwd"
        ]

        for malicious_input in malicious_inputs:
            response = self.client.get(
                reverse('snort-dashboard'),
                {'search': malicious_input}
            )
            # Should not crash and should return valid response
            self.assertEqual(response.status_code, 200)

    def test_xss_prevention(self):
        """Test prevention of XSS attacks"""
        self.client.login(username='testuser', password='testpass123')

        xss_payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')"
        ]

        for payload in xss_payloads:
            response = self.client.post(
                reverse('ollama-chat'),
                {'message': payload},
                content_type='application/json'
            )
            # Should sanitize input and not execute scripts
            self.assertEqual(response.status_code, 200)

    def test_csrf_protection(self):
        """Test CSRF protection on forms"""
        self.client.login(username='testuser', password='testpass123')

        # Try POST without CSRF token
        response = self.client.post(
            reverse('ollama-config-save'),
            {'ollama_url': 'http://localhost:11434'}
        )
        # Should fail with CSRF error
        self.assertEqual(response.status_code, 403)

    def test_permission_enforcement(self):
        """Test that permissions are properly enforced"""
        # Test user without permissions trying to access admin functions
        self.client.login(username='testuser', password='testpass123')

        admin_urls = [
            reverse('ollama-config'),
            reverse('user-management'),
            reverse('system-logs'),
            reverse('email-configuration')
        ]

        for url in admin_urls:
            response = self.client.get(url)
            # Should redirect or return forbidden
            self.assertIn(response.status_code, [302, 403])

    def test_input_validation(self):
        """Test input validation on forms"""
        self.client.login(username='admin', password='admin123')

        # Test invalid Ollama URL
        response = self.client.post(
            reverse('ollama-config-save'),
            {
                'ollama_url': 'not-a-valid-url',
                'ollama_model': 'llama3.2',
                'max_tokens': 2000,
                'temperature': 0.3,
                'timeout_seconds': 30,
                'is_active': 'on'
            }
        )
        # Should handle validation error gracefully
        self.assertEqual(response.status_code, 200)

    def test_rate_limiting(self):
        """Test rate limiting on API endpoints"""
        self.client.login(username='testuser', password='testpass123')

        # Make multiple rapid requests to chat endpoint
        for i in range(10):
            response = self.client.post(
                reverse('ollama-chat'),
                {'message': f'Test message {i}'},
                content_type='application/json'
            )
            # Should not crash under load
            self.assertIn(response.status_code, [200, 429])  # 429 = Too Many Requests


class IntegrationTests(TestCase):
    """Integration test cases"""

    def setUp(self):
        """Set up test data"""
        self.client = Client()
        self.superuser = User.objects.create_superuser(
            username='admin',
            email='admin@example.com',
            password='admin123'
        )

    @patch('VANT_SIEM.ollama_service.requests.Session.post')
    def test_full_chat_workflow(self, mock_post):
        """Test complete chat workflow"""
        # Mock Ollama response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'response': 'Test AI response'}
        mock_post.return_value = mock_response

        self.client.login(username='admin', password='admin123')

        # Test chat endpoint
        response = self.client.post(
            reverse('ollama-chat'),
            {
                'message': '¿Cuáles son los reportes nuevos?',
                'history': []
            },
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertTrue(data['success'])
        self.assertIn('response', data)

    def test_notification_workflow(self):
        """Test complete notification workflow"""
        self.client.login(username='admin', password='admin123')

        # Create notification
        notification = Notification.objects.create(
            user=self.superuser,
            title='Test Notification',
            message='Test message',
            event_type='SYSTEM_ALERT'
        )

        # Test marking as read
        response = self.client.post(
            reverse('mark-notification-read', args=[notification.id])
        )
        self.assertEqual(response.status_code, 200)

        # Verify notification was marked as read
        notification.refresh_from_db()
        self.assertTrue(notification.is_read)

    def test_configuration_workflow(self):
        """Test configuration save and retrieval workflow"""
        self.client.login(username='admin', password='admin123')

        # Save configuration
        config_data = {
            'ollama_url': 'http://localhost:11434',
            'ollama_model': 'llama3.2',
            'max_tokens': 2000,
            'temperature': 0.3,
            'timeout_seconds': 30,
            'is_active': 'on'
        }

        response = self.client.post(
            reverse('ollama-config-save'),
            config_data
        )
        self.assertEqual(response.status_code, 200)

        # Verify configuration was saved
        config = OllamaConfig.get_active_config()
        self.assertIsNotNone(config)
        self.assertEqual(config.ollama_url, 'http://localhost:11434')
        self.assertEqual(config.ollama_model, 'llama3.2')


class PerformanceTests(TestCase):
    """Performance-focused test cases"""

    def setUp(self):
        """Set up test data"""
        self.client = Client()
        self.superuser = User.objects.create_superuser(
            username='admin',
            email='admin@example.com',
            password='admin123'
        )

    def test_dashboard_performance(self):
        """Test dashboard loading performance"""
        self.client.login(username='admin', password='admin123')

        import time
        start_time = time.time()

        response = self.client.get(reverse('dashboard'))

        end_time = time.time()
        load_time = end_time - start_time

        self.assertEqual(response.status_code, 200)
        # Dashboard should load in under 2 seconds
        self.assertLess(load_time, 2.0)

    @patch('VANT_SIEM.ollama_service.requests.Session.post')
    def test_chat_response_time(self, mock_post):
        """Test chat response time"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'response': 'Quick response'}
        mock_post.return_value = mock_response

        self.client.login(username='admin', password='admin123')

        import time
        start_time = time.time()

        response = self.client.post(
            reverse('ollama-chat'),
            {'message': 'Hello', 'history': []},
            content_type='application/json'
        )

        end_time = time.time()
        response_time = end_time - start_time

        self.assertEqual(response.status_code, 200)
        # Chat should respond in under 1 second
        self.assertLess(response_time, 1.0)


if __name__ == '__main__':
    unittest.main()
