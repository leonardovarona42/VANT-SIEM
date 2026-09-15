from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from soc_app.models import Incidente, Reporte

class SocApiTests(APITestCase):
    def setUp(self):
        # Setup some test data
        self.incidente = Incidente.objects.create(
            nombre_incidente="Test Incident",
            descripcion="Test description",
            estado_solucion="nuevo"
        )
        self.list_url = reverse('incidentelist') # Check if the name is correct

    def test_unauthenticated_access_denied(self):
        """Verify that unauthenticated requests are rejected (SEC-01)."""
        response = self.client.get(self.list_url)
        # Depending on the config, it might be 401 or 403
        self.assertIn(response.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN])

    def test_incident_creation_authenticated(self):
        """Test creating an incident when authenticated."""
        # We mock the authentication by adding the required attributes to the request
        # or by creating a valid token if we had the auth service running.
        # For unit tests, we can manually set the user in the request.
        from django.contrib.auth.models import User
        user = User.objects.create_user(username="admin", password="password")
        self.client.force_authenticate(user=user)

        data = {
            "nombre_incidente": "New Incident",
            "descripcion": "New description",
            "estado_solucion": "nuevo"
        }
        response = self.client.post(self.list_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Incidente.objects.count(), 2)
