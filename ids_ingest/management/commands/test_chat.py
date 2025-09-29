from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from VANT_SIEM.views import _generate_fallback_response
import json

class Command(BaseCommand):
    help = 'Test the chat fallback response system'

    def handle(self, *args, **options):
        # Test messages
        test_messages = [
            "revisa si hay reportes nuevos",
            "dime los reportes nuevos",
            "¿hay incidentes activos?",
            "¿cuáles son las amenazas recientes?",
            "qué está pasando en el sistema"
        ]

        # Mock context parts (simplified)
        context_parts = [
            "CONTEXTO ACTUAL DEL SISTEMA:",
            "- Alertas últimas 24h: 15",
            "- Alertas última hora: 3 (1 críticas)",
            "- Logs Snort/hora: 25",
            "- Logs Suricata/hora: 18",
            "- Reportes totales: 5",
            "- Incidentes activos: 2"
        ]

        # Mock specific data
        specific_data = {
            'recent_reports': [
                {
                    'titulo': 'Análisis de Tráfico Sospechoso',
                    'estado': 'PENDIENTE',
                    'area': 'Seguridad de Red',
                    'fecha': '22/09/2024 14:30',
                    'dias_antiguedad': 0
                },
                {
                    'titulo': 'Auditoría de Logs del Sistema',
                    'estado': 'COMPLETADO',
                    'area': 'Monitoreo',
                    'fecha': '20/09/2024 16:45',
                    'dias_antiguedad': 2
                }
            ],
            'incidents': [
                {
                    'titulo': 'Acceso No Autorizado Detectado',
                    'estado': 'EN_PROGRESO',
                    'categoria': 'Acceso',
                    'fecha': '22/09/2024 10:15',
                    'es_reciente': True
                }
            ],
            'critical_alerts': [
                {
                    'mensaje': 'Intento de SQL Injection',
                    'severidad': 'Critical',
                    'ip_origen': '192.168.1.100',
                    'ip_destino': '10.0.0.1',
                    'timestamp': '22/09/2024 15:30'
                }
            ]
        }

        self.stdout.write(self.style.SUCCESS('Testing chat fallback responses:\n'))

        for message in test_messages:
            self.stdout.write(self.style.WARNING(f'Input: "{message}"'))
            response = _generate_fallback_response(message, specific_data, context_parts)
            self.stdout.write(self.style.SUCCESS(f'Response: {response}\n'))
            self.stdout.write('-' * 80)