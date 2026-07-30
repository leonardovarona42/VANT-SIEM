from django.core.management.base import BaseCommand

from bus_app.models import (
    GroupAlertSubscription,
    NotificationGroup,
    ServiceConfig,
)


class Command(BaseCommand):
    help = "Seed vant-bus with initial groups, subscriptions, and service configs"

    def handle(self, *args, **options):
        self._seed_groups()
        self._seed_subscriptions()
        self._seed_services()
        self.stdout.write(self.style.SUCCESS("Seeding complete"))

    def _seed_groups(self):
        groups = {
            "Administradores de la Red": "Acceso total al sistema. Recibe todas las alertas y eventos.",
            "Especialistas de Ciberseguridad": "Equipo de seguridad. Recibe alertas de incidentes, amenazas DLP y servicios caídos.",
            "RSI de las Áreas": "Responsables de Seguridad de la Información por área. Reciben reportes y eventos de su área.",
            "Cuadros de las Áreas": "Jefos de Departamento y Directores. Reciben reportes e incidentes relevantes.",
            "Grupo de Trabajo de Ciberseguridad": "Todos los miembros anteriores. Recibe todo.",
        }
        for name, desc in groups.items():
            NotificationGroup.objects.get_or_create(name=name, defaults={"description": desc})
        self.stdout.write(f"  Groups: {NotificationGroup.objects.count()}")

    def _seed_subscriptions(self):
        all_event_types = [
            "reporte_creado", "reporte_editado", "reporte_eliminado", "reporte_rechazado",
            "incidente_creado", "incidente_editado", "incidente_estado_cambiado", "incidente_eliminado",
            "login_bloqueado", "usuario_creado", "usuario_desabilitado",
            "servicio_down", "servicio_up", "servicio_restart", "servicio_stop",
            "amenaza_dlp",
        ]

        admin_group = NotificationGroup.objects.get(name="Administradores de la Red")
        for evt in all_event_types:
            for ch in ("email", "dashboard"):
                GroupAlertSubscription.objects.get_or_create(
                    group=admin_group, event_type=evt, channel=ch,
                )

        csirt_group = NotificationGroup.objects.get(name="Especialistas de Ciberseguridad")
        csirt_events = [
            "incidente_creado", "incidente_editado", "incidente_estado_cambiado", "incidente_eliminado",
            "servicio_down", "servicio_up",
            "amenaza_dlp",
            "login_bloqueado",
        ]
        for evt in csirt_events:
            for ch in ("email", "dashboard"):
                GroupAlertSubscription.objects.get_or_create(
                    group=csirt_group, event_type=evt, channel=ch,
                )

        rsi_group = NotificationGroup.objects.get(name="RSI de las Áreas")
        rsi_events = ["reporte_creado", "reporte_editado", "reporte_rechazado", "incidente_creado", "incidente_estado_cambiado"]
        for evt in rsi_events:
            GroupAlertSubscription.objects.get_or_create(
                group=rsi_group, event_type=evt, channel="dashboard",
            )

        cuadros_group = NotificationGroup.objects.get(name="Cuadros de las Áreas")
        cuadros_events = ["reporte_creado", "reporte_rechazado", "incidente_creado", "incidente_estado_cambiado"]
        for evt in cuadros_events:
            for ch in ("email", "dashboard"):
                GroupAlertSubscription.objects.get_or_create(
                    group=cuadros_group, event_type=evt, channel=ch,
                )

        gciber_group = NotificationGroup.objects.get(name="Grupo de Trabajo de Ciberseguridad")
        for evt in all_event_types:
            GroupAlertSubscription.objects.get_or_create(
                group=gciber_group, event_type=evt, channel="dashboard",
            )

        self.stdout.write(f"  Subscriptions: {GroupAlertSubscription.objects.count()}")

    def _seed_services(self):
        services = [
            {"name": "vant-auth", "display_name": "Servicio de Autenticación", "port": 8100, "systemd_service": "vantsiem-auth", "is_critical": True},
            {"name": "vant-web", "display_name": "Dashboard Web", "port": 8200, "systemd_service": "vantsiem-web", "is_critical": True},
            {"name": "vant-inventory", "display_name": "Inventario de Agentes", "port": 8300, "systemd_service": "vantsiem-inventory", "is_critical": False},
            {"name": "vant-logs", "display_name": "Recolección de Logs", "port": 8400, "systemd_service": "vantsiem-logs", "is_critical": True},
            {"name": "vant-soc", "display_name": "SOC - Centro de Operaciones", "port": 8500, "systemd_service": "vantsiem-soc", "is_critical": True},
            {"name": "vant-bus", "display_name": "Event Bus y Notificaciones", "port": 8600, "systemd_service": "vantsiem-bus", "is_critical": True},
        ]
        for s in services:
            ServiceConfig.objects.get_or_create(name=s["name"], defaults=s)
        self.stdout.write(f"  Services: {ServiceConfig.objects.count()}")
