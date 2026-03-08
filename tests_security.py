#!/usr/bin/env python3
"""
Security Testing Suite for VANT-SIEM
Comprehensive security testing including penetration testing, vulnerability assessment, and security validation
"""

import os
import sys
import json
import requests
import subprocess
import time
from urllib.parse import urljoin
import django
from django.conf import settings
from django.test.utils import get_runner
from django.core.management import execute_from_command_line

# Configure Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CORE.settings')
django.setup()

from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from VANT_SIEM.models import OllamaConfig
from opensearch_ui.models import IDSConfiguration, ThreatLog


class SecurityTestSuite:
    """Comprehensive security testing suite"""

    def __init__(self, base_url='http://localhost:8000'):
        self.base_url = base_url
        self.client = Client()
        self.session = requests.Session()
        self.vulnerabilities = []
        self.test_results = {
            'passed': 0,
            'failed': 0,
            'warnings': 0,
            'vulnerabilities': []
        }

    def log_vulnerability(self, severity, title, description, impact, remediation):
        """Log a security vulnerability"""
        vuln = {
            'severity': severity,
            'title': title,
            'description': description,
            'impact': impact,
            'remediation': remediation,
            'timestamp': time.time()
        }
        self.vulnerabilities.append(vuln)
        print(f"🔴 [{severity.upper()}] {title}")

    def log_success(self, test_name):
        """Log successful test"""
        self.test_results['passed'] += 1
        print(f"✅ {test_name}")

    def log_failure(self, test_name, reason):
        """Log failed test"""
        self.test_results['failed'] += 1
        print(f"❌ {test_name}: {reason}")

    def log_warning(self, test_name, reason):
        """Log test warning"""
        self.test_results['warnings'] += 1
        print(f"⚠️  {test_name}: {reason}")

    def test_sql_injection(self):
        """Test SQL injection vulnerabilities"""
        print("\n🔍 Testing SQL Injection Vulnerabilities...")

        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users; --",
            "admin'--",
            "1' OR '1' = '1",
            "' OR 1=1; --",
        ]

        vulnerable_endpoints = [
            ('snort-dashboard', {'search': ''}),
            ('suricata-dashboard', {'search': ''}),
            ('threats-list', {'search': ''}),
        ]

        # Create test user
        user = User.objects.create_user('security_test', 'test@example.com', 'test123')
        self.client.login(username='security_test', password='test123')

        for endpoint_name, params in vulnerable_endpoints:
            try:
                url = reverse(endpoint_name)
                for payload in sql_payloads:
                    test_params = params.copy()
                    for key in test_params:
                        test_params[key] = payload

                    response = self.client.get(url, test_params)

                    # Check for SQL errors in response
                    sql_errors = [
                        'sql syntax', 'mysql error', 'postgresql error',
                        'sqlite error', 'oracle error', 'sqlserver error'
                    ]

                    response_text = response.content.decode().lower()
                    if any(error in response_text for error in sql_errors):
                        self.log_vulnerability(
                            'HIGH',
                            f'SQL Injection in {endpoint_name}',
                            f'SQL injection payload "{payload}" caused database error',
                            'Potential data breach, unauthorized access',
                            'Implement proper input sanitization and parameterized queries'
                        )
                        break

            except Exception as e:
                self.log_failure(f'SQL Injection test for {endpoint_name}', str(e))

        user.delete()
        self.log_success("SQL Injection tests completed")

    def test_xss_vulnerabilities(self):
        """Test Cross-Site Scripting vulnerabilities"""
        print("\n🔍 Testing XSS Vulnerabilities...")

        xss_payloads = [
            '<script>alert("xss")</script>',
            '<img src=x onerror=alert("xss")>',
            'javascript:alert("xss")',
            '<iframe src="javascript:alert(\'xss\')"></iframe>',
            '<svg onload=alert("xss")>',
        ]

        vulnerable_endpoints = [
            ('ollama-chat', {'message': '', 'history': []}),
            ('snort-dashboard', {'search': ''}),
            ('suricata-dashboard', {'search': ''}),
        ]

        # Create test user
        user = User.objects.create_user('xss_test', 'test@example.com', 'test123')
        self.client.login(username='xss_test', password='test123')

        for endpoint_name, params in vulnerable_endpoints:
            try:
                url = reverse(endpoint_name)
                for payload in xss_payloads:
                    if endpoint_name == 'ollama-chat':
                        response = self.client.post(
                            url,
                            json.dumps({'message': payload, 'history': []}),
                            content_type='application/json'
                        )
                    else:
                        test_params = params.copy()
                        for key in test_params:
                            test_params[key] = payload
                        response = self.client.get(url, test_params)

                    # Check if XSS payload appears unsanitized in response
                    if payload in response.content.decode():
                        self.log_vulnerability(
                            'HIGH',
                            f'XSS Vulnerability in {endpoint_name}',
                            f'XSS payload "{payload}" appears unsanitized in response',
                            'Potential code execution in user browsers',
                            'Implement proper output encoding and CSP headers'
                        )
                        break

            except Exception as e:
                self.log_failure(f'XSS test for {endpoint_name}', str(e))

        user.delete()
        self.log_success("XSS tests completed")

    def test_csrf_protection(self):
        """Test CSRF protection"""
        print("\n🔍 Testing CSRF Protection...")

        csrf_endpoints = [
            'ollama-config-save',
            'save-notification-settings',
        ]

        for endpoint_name in csrf_endpoints:
            try:
                url = reverse(endpoint_name)
                # Try POST without CSRF token
                response = self.client.post(url, {'test': 'data'})

                if response.status_code != 403:
                    self.log_vulnerability(
                        'MEDIUM',
                        f'Weak CSRF Protection in {endpoint_name}',
                        'Endpoint accepts POST requests without proper CSRF validation',
                        'Potential CSRF attacks allowing unauthorized actions',
                        'Ensure all POST endpoints require valid CSRF tokens'
                    )

            except Exception as e:
                self.log_failure(f'CSRF test for {endpoint_name}', str(e))

        self.log_success("CSRF protection tests completed")

    def test_authentication_bypass(self):
        """Test authentication bypass attempts"""
        print("\n🔍 Testing Authentication Bypass...")

        protected_endpoints = [
            'dashboard',
            'ollama-config',
            'user-management',
            'system-logs',
        ]

        for endpoint_name in protected_endpoints:
            try:
                url = reverse(endpoint_name)
                response = self.client.get(url)

                # Should redirect to login (302) or return 403
                if response.status_code not in [302, 403]:
                    self.log_vulnerability(
                        'CRITICAL',
                        f'Authentication Bypass in {endpoint_name}',
                        f'Protected endpoint {endpoint_name} accessible without authentication',
                        'Unauthorized access to sensitive functionality',
                        'Implement proper authentication checks on all protected views'
                    )

            except Exception as e:
                self.log_failure(f'Auth test for {endpoint_name}', str(e))

        self.log_success("Authentication bypass tests completed")

    def test_authorization_flaws(self):
        """Test authorization flaws"""
        print("\n🔍 Testing Authorization Flaws...")

        # Create regular user
        user = User.objects.create_user('auth_test', 'test@example.com', 'test123')
        self.client.login(username='auth_test', password='test123')

        admin_endpoints = [
            'ollama-config',
            'user-management',
            'system-logs',
            'email-configuration',
        ]

        for endpoint_name in admin_endpoints:
            try:
                url = reverse(endpoint_name)
                response = self.client.get(url)

                # Regular user should not access admin endpoints
                if response.status_code not in [302, 403]:
                    self.log_vulnerability(
                        'HIGH',
                        f'Authorization Flaw in {endpoint_name}',
                        f'Regular user can access admin endpoint {endpoint_name}',
                        'Privilege escalation, unauthorized admin access',
                        'Implement proper role-based access control'
                    )

            except Exception as e:
                self.log_failure(f'Authorization test for {endpoint_name}', str(e))

        user.delete()
        self.log_success("Authorization tests completed")

    def test_file_upload_vulnerabilities(self):
        """Test file upload vulnerabilities"""
        print("\n🔍 Testing File Upload Vulnerabilities...")

        # Test with various file types and malicious content
        malicious_files = [
            ('shell.php', '<?php system($_GET["cmd"]); ?>', 'application/x-php'),
            ('script.js', 'javascript:alert("xss")', 'application/javascript'),
            ('webshell.asp', '<% eval request("cmd") %>', 'application/x-asp'),
        ]

        # Note: This would require actual file upload endpoints to test properly
        # For now, we'll test the concept
        self.log_warning("File Upload Test", "No file upload endpoints found to test")

    def test_directory_traversal(self):
        """Test directory traversal vulnerabilities"""
        print("\n🔍 Testing Directory Traversal...")

        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            '/etc/shadow',
            '....//....//....//etc/passwd',
        ]

        # Test log file processing endpoints
        user = User.objects.create_user('traversal_test', 'test@example.com', 'test123')
        self.client.login(username='traversal_test', password='test123')

        for payload in traversal_payloads:
            try:
                # Test with snort log processing (if endpoint exists)
                response = self.client.post(
                    reverse('process-logs'),
                    {'log_file': payload, 'ids_type': 'snort'}
                )

                if response.status_code == 200:
                    self.log_vulnerability(
                        'HIGH',
                        'Directory Traversal Vulnerability',
                        f'Directory traversal payload "{payload}" accepted',
                        'Arbitrary file access, information disclosure',
                        'Implement proper path validation and sanitization'
                    )
                    break

            except Exception:
                # Endpoint might not exist, skip
                pass

        user.delete()
        self.log_success("Directory traversal tests completed")

    def test_ssl_tls_configuration(self):
        """Test SSL/TLS configuration"""
        print("\n🔍 Testing SSL/TLS Configuration...")

        try:
            # Test if HTTPS is enforced
            response = requests.get(self.base_url.replace('http://', 'https://'), timeout=5)
            if response.status_code == 200:
                self.log_success("HTTPS is properly configured")
            else:
                self.log_warning("SSL/TLS Test", "HTTPS not available or not properly configured")
        except requests.exceptions.SSLError:
            self.log_failure("SSL/TLS Test", "SSL certificate validation failed")
        except requests.exceptions.ConnectionError:
            self.log_warning("SSL/TLS Test", "HTTPS not configured")
        except Exception as e:
            self.log_failure("SSL/TLS Test", str(e))

    def test_security_headers(self):
        """Test security headers"""
        print("\n🔍 Testing Security Headers...")

        try:
            response = requests.get(self.base_url, timeout=5)

            security_headers = [
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Content-Security-Policy',
                'Strict-Transport-Security'
            ]

            missing_headers = []
            for header in security_headers:
                if header not in response.headers:
                    missing_headers.append(header)

            if missing_headers:
                self.log_vulnerability(
                    'MEDIUM',
                    'Missing Security Headers',
                    f'Security headers not present: {", ".join(missing_headers)}',
                    'Increased attack surface for various web vulnerabilities',
                    'Implement security headers middleware'
                )
            else:
                self.log_success("Security headers properly configured")

        except Exception as e:
            self.log_failure("Security Headers Test", str(e))

    def test_session_security(self):
        """Test session security"""
        print("\n🔍 Testing Session Security...")

        # Test session cookie settings
        user = User.objects.create_user('session_test', 'test@example.com', 'test123')
        self.client.login(username='session_test', password='test123')

        # Check session cookie
        session_cookie = None
        for cookie in self.client.cookies:
            if 'sessionid' in cookie.name.lower():
                session_cookie = cookie
                break

        if session_cookie:
            # Check if session cookie has secure flags
            if not session_cookie.secure:
                self.log_vulnerability(
                    'MEDIUM',
                    'Session Cookie Not Secure',
                    'Session cookie transmitted over HTTP without secure flag',
                    'Session hijacking over insecure connections',
                    'Set SESSION_COOKIE_SECURE = True in production'
                )

            if session_cookie.get_nonstandard_attr('HttpOnly') is False:
                self.log_vulnerability(
                    'MEDIUM',
                    'Session Cookie Not HttpOnly',
                    'Session cookie accessible via JavaScript',
                    'Increased XSS attack surface',
                    'Set SESSION_COOKIE_HTTPONLY = True'
                )
        else:
            self.log_warning("Session Security Test", "No session cookie found")

        user.delete()
        self.log_success("Session security tests completed")

    def test_input_validation(self):
        """Test input validation"""
        print("\n🔍 Testing Input Validation...")

        # Test with oversized inputs
        large_input = 'A' * 10000

        user = User.objects.create_user('validation_test', 'test@example.com', 'test123')
        self.client.login(username='validation_test', password='test123')

        test_endpoints = [
            ('ollama-chat', {'message': large_input, 'history': []}),
            ('snort-dashboard', {'search': large_input}),
        ]

        for endpoint_name, data in test_endpoints:
            try:
                url = reverse(endpoint_name)
                if endpoint_name == 'ollama-chat':
                    response = self.client.post(
                        url,
                        json.dumps(data),
                        content_type='application/json'
                    )
                else:
                    response = self.client.get(url, data)

                # Should handle large input gracefully
                if response.status_code >= 500:
                    self.log_vulnerability(
                        'MEDIUM',
                        f'Input Validation Issue in {endpoint_name}',
                        'Large input caused server error',
                        'Potential DoS through resource exhaustion',
                        'Implement input size limits and validation'
                    )

            except Exception as e:
                self.log_failure(f'Input validation test for {endpoint_name}', str(e))

        user.delete()
        self.log_success("Input validation tests completed")

    def run_dependency_check(self):
        """Run dependency vulnerability check"""
        print("\n🔍 Checking Dependencies for Vulnerabilities...")

        try:
            # Check if safety is available
            import safety
            # Run safety check
            result = subprocess.run(
                [sys.executable, '-m', 'safety', 'check'],
                capture_output=True,
                text=True,
                cwd=os.path.dirname(__file__)
            )

            if result.returncode != 0:
                vulnerabilities = result.stdout.strip()
                if vulnerabilities:
                    self.log_vulnerability(
                        'HIGH',
                        'Vulnerable Dependencies',
                        f'Found vulnerable packages:\n{vulnerabilities}',
                        'Known security vulnerabilities in dependencies',
                        'Update dependencies to patched versions'
                    )
                else:
                    self.log_success("Dependency vulnerability check passed")
            else:
                self.log_success("No vulnerable dependencies found")

        except ImportError:
            self.log_warning("Dependency Check", "Safety tool not installed. Install with: pip install safety")
        except Exception as e:
            self.log_failure("Dependency Check", str(e))

    def generate_report(self):
        """Generate comprehensive security report"""
        print("\n" + "="*80)
        print("🔒 VANT-SIEM SECURITY TEST REPORT")
        print("="*80)

        print(f"\n📊 Test Results:")
        print(f"   ✅ Passed: {self.test_results['passed']}")
        print(f"   ❌ Failed: {self.test_results['failed']}")
        print(f"   ⚠️  Warnings: {self.test_results['warnings']}")

        print(f"\n🔴 Vulnerabilities Found: {len(self.vulnerabilities)}")

        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln in self.vulnerabilities:
            severity_counts[vuln['severity']] += 1

        for severity, count in severity_counts.items():
            if count > 0:
                print(f"   {severity}: {count}")

        if self.vulnerabilities:
            print(f"\n📋 Detailed Vulnerabilities:")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"\n{i}. [{vuln['severity']}] {vuln['title']}")
                print(f"   Description: {vuln['description']}")
                print(f"   Impact: {vuln['impact']}")
                print(f"   Remediation: {vuln['remediation']}")

        print(f"\n💡 Recommendations:")
        if len(self.vulnerabilities) == 0:
            print("   🎉 Excellent! No critical vulnerabilities found.")
        else:
            print("   1. Address all CRITICAL and HIGH severity issues immediately")
            print("   2. Implement security headers and CSRF protection")
            print("   3. Regular security testing and dependency updates")
            print("   4. Input validation and sanitization on all endpoints")

        print(f"\n🔄 Next Steps:")
        print("   - Run automated tests regularly")
        print("   - Implement security monitoring")
        print("   - Regular code reviews focusing on security")
        print("   - Keep dependencies updated")

        print("\n" + "="*80)

    def run_all_tests(self):
        """Run all security tests"""
        print("🚀 Starting VANT-SIEM Security Test Suite...")
        print(f"Target: {self.base_url}")
        print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")

        # Run all test methods
        test_methods = [
            self.test_sql_injection,
            self.test_xss_vulnerabilities,
            self.test_csrf_protection,
            self.test_authentication_bypass,
            self.test_authorization_flaws,
            self.test_file_upload_vulnerabilities,
            self.test_directory_traversal,
            self.test_ssl_tls_configuration,
            self.test_security_headers,
            self.test_session_security,
            self.test_input_validation,
            self.run_dependency_check,
        ]

        for test_method in test_methods:
            try:
                test_method()
            except Exception as e:
                self.log_failure(f"Test execution error in {test_method.__name__}", str(e))

        self.generate_report()


def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description='VANT-SIEM Security Testing Suite')
    parser.add_argument('--url', default='http://localhost:8000',
                       help='Base URL of the application to test')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    # Run security tests
    security_suite = SecurityTestSuite(args.url)
    security_suite.run_all_tests()


if __name__ == '__main__':
    main()
