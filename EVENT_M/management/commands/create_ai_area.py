from django.core.management.base import BaseCommand
from EVENT_M.models import Area, Responsable

class Command(BaseCommand):
    help = 'Crear área VANT-SIEM-AI-Analitic para reportes automáticos de IA'

    def handle(self, *args, **options):
        # Verificar si ya existe el área
        if Area.objects.filter(nombre='VANT-SIEM-AI-Analitic').exists():
            self.stdout.write(self.style.WARNING('El área VANT-SIEM-AI-Analitic ya existe'))
            return

        # Crear responsables si no existen
        admin_responsable, created = Responsable.objects.get_or_create(
            nombres='VANT-SIEM',
            apellidos='AI System',
            defaults={
                'email': 'ai@vantsiem.local',
                'telefono_particular': '+53-00000000',
                'telefono_corp': '+53-00000000',
                'tipo': 'Sistema Automático',
                'descripcion': 'Sistema de IA automatizado para análisis de seguridad'
            }
        )

        if created:
            self.stdout.write(f'Creado responsable: {admin_responsable}')

        # Crear área con el mismo responsable para todos los roles
        area = Area.objects.create(
            nombre='VANT-SIEM-AI-Analitic',
            acronimo='VANT-AI',
            cuadro_centro=admin_responsable,
            rsi=admin_responsable,
            admin=admin_responsable
        )

        self.stdout.write(
            self.style.SUCCESS(f'Área creada exitosamente: {area.nombre} ({area.acronimo})')
        )