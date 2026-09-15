import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from auth_app.models import AuthUser

class AuthTests(APITestCase):
    def setUp(self):
        # Create a test user
        self.username = "testuser"
        self.password = "testpass123"
        self.user = AuthUser.objects.create(
            username=self.username,
            email="test@example.com",
            password_hash="", # set_password will be used
            role="viewer"
        )
        self.user.set_password(self.password)
        self.user.save()

        self.login_url = reverse('login') # I need to check if the name is 'login'

    def test_login_success(self):
        """Test successful login with valid credentials."""
        data = {
            "username": self.username,
            "password": self.password
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)
        self.assertEqual(response.data["user"]["username"], self.username)

    def test_login_invalid_password(self):
        """Test login failure with wrong password."""
        data = {
            "username": self.username,
            "password": "wrongpassword"
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn("error", response.data)

    def test_login_inactive_user(self):
        """Test login failure for inactive user."""
        self.user.is_active = False
        self.user.save()
        data = {
            "username": self.username,
            "password": self.password
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("disabled", response.data["error"])

    def test_login_lockout(self):
        """Test account lockout after too many failed attempts."""
        # 5 failed attempts
        for _ in range(5):
            self.client.post(self.login_url, {"username": self.username, "password": "bad"}, format='json')

        # 6th attempt should be locked
        data = {
            "username": self.username,
            "password": self.password
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("locked", response.data["error"])

    def test_agent_register_unauthorized(self):
        """Verify that agent registration requires service secret (SEC-05)."""
        url = reverse('agent_register')
        data = {"agent_id": "test_agent", "hostname": "test_host"}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["error"], "forbidden")

    def test_agent_register_authorized(self):
        """Verify agent registration with correct service secret."""
        url = reverse('agent_register')
        data = {"agent_id": "test_agent", "hostname": "test_host"}
        # Mock the service secret header
        self.client.defaults()
        self.client.defaults['headers'] = {"X-Service-Secret": "changeme-service-secret"}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("token", response.data)

