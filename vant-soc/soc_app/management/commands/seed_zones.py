import os, sys
from django.core.management.base import BaseCommand
from soc_app.models import Servicio


class Command(BaseCommand):
    help = "Seed zones and hierarchy for VANT-SIEM topology"

    def handle(self, *args, **options):
        self._run()

    def _run(self):
        def get_svc(name):
            return Servicio.objects.filter(nombre=name).first()

        def create_zone(nombre, x, y, w, h, color_fondo, color_borde, descripcion=""):
            z, _ = Servicio.objects.update_or_create(
                nombre=nombre,
                defaults={
                    "tipo": "zona",
                    "descripcion": descripcion,
                    "coordenadas_logicas_x": x,
                    "coordenadas_logicas_y": y,
                    "zona_ancho": w,
                    "zona_alto": h,
                    "zona_color_fondo": color_fondo,
                    "zona_color_borde": color_borde,
                    "activo": True,
                },
            )
            self.stdout.write(f"  Zona: {z.nombre} (id={z.id})")
            return z

        def create_dc(nombre, x, y, w, h, color_fondo, color_borde, descripcion=""):
            z, _ = Servicio.objects.update_or_create(
                nombre=nombre,
                defaults={
                    "tipo": "datacenter",
                    "descripcion": descripcion,
                    "coordenadas_logicas_x": x,
                    "coordenadas_logicas_y": y,
                    "zona_ancho": w,
                    "zona_alto": h,
                    "zona_color_fondo": color_fondo,
                    "zona_color_borde": color_borde,
                    "activo": True,
                },
            )
            self.stdout.write(f"  Datacenter: {z.nombre} (id={z.id})")
            return z

        def assign_child(parent, child_name, x, y):
            child = get_svc(child_name)
            if child:
                child.servicio_padre = parent
                child.coordenadas_logicas_x = x
                child.coordenadas_logicas_y = y
                child.save()
                self.stdout.write(f"    -> {child_name} (id={child.id}) assigned to {parent.nombre}")
            else:
                self.stdout.write(f"    !! {child_name} NOT FOUND")

        def create_vlan(nombre, x, y, parent, vlan_id=None, red_tipo="interna", network=""):
            v, created = Servicio.objects.update_or_create(
                nombre=nombre,
                defaults={
                    "tipo": "vlan",
                    "vlan_id": vlan_id,
                    "red_tipo": red_tipo,
                    "network": network,
                    "servicio_padre": parent,
                    "coordenadas_logicas_x": x,
                    "coordenadas_logicas_y": y,
                    "activo": True,
                },
            )
            action = "Created" if created else "Updated"
            self.stdout.write(f"    -> {action}: {nombre} (id={v.id})")
            return v

        self.stdout.write("=" * 60)
        self.stdout.write("SEED: Zones and topology hierarchy")
        self.stdout.write("=" * 60)

        dc = create_dc(
            "Corporativa DTCM", x=0, y=0, w=1400, h=900,
            color_fondo="rgba(245,158,11,0.06)", color_borde="#f59e0b",
            descripcion="Datacenter principal Corporativa DTCM",
        )

        z_dmz_ext = create_zone(
            "DMZ-Externa", x=-450, y=-300, w=380, h=280,
            color_fondo="rgba(239,68,68,0.10)", color_borde="#ef4444",
            descripcion="Zona DMZ Externa - perimetral",
        )
        assign_child(z_dmz_ext, "Router-Edge-01", -550, -370)
        assign_child(z_dmz_ext, "FW-Principal", -380, -370)

        z_dmz_int = create_zone(
            "DMZ-Interna", x=400, y=-300, w=380, h=280,
            color_fondo="rgba(239,68,68,0.06)", color_borde="#dc2626",
            descripcion="Zona DMZ Interna - publicaciones",
        )
        assign_child(z_dmz_int, "AP-Torre-01", 320, -370)
        assign_child(z_dmz_int, "AP-Torre-02", 480, -370)
        assign_child(z_dmz_int, "VLAN-DMZ", 400, -230)

        z_red_corp = create_zone(
            "Red Corporativa", x=-450, y=100, w=420, h=300,
            color_fondo="rgba(59,130,246,0.10)", color_borde="#3b82f6",
            descripcion="Red corporativa - switches y usuarios",
        )
        assign_child(z_red_corp, "Core-Switch-01", -580, 30)
        assign_child(z_red_corp, "Dist-Switch-01", -420, 30)
        assign_child(z_red_corp, "Dist-Switch-02", -300, 30)
        assign_child(z_red_corp, "VLAN-Usuarios", -480, 150)
        assign_child(z_red_corp, "VLAN-Admin", -340, 150)
        assign_child(z_red_corp, "Red-Corporativa", -410, 250)

        z_serv = create_zone(
            "Zona Servidores", x=400, y=100, w=420, h=300,
            color_fondo="rgba(168,85,247,0.10)", color_borde="#a855f7",
            descripcion="Servidores de aplicaciones y base de datos",
        )
        assign_child(z_serv, "SV-DC-01", 310, 30)
        assign_child(z_serv, "SV-DC-02", 420, 30)
        assign_child(z_serv, "SV-Web-01", 530, 30)
        assign_child(z_serv, "SV-BD-01", 310, 150)
        assign_child(z_serv, "SV-Testing", 420, 150)
        assign_child(z_serv, "VLAN-Servidores", 530, 150)
        assign_child(z_serv, "NAS-Backup-01", 360, 250)
        assign_child(z_serv, "UPS-Rack-01", 480, 250)
        assign_child(z_serv, "Plataforma-SIEM", 420, 350)

        z_oss = create_zone(
            "Red OSS", x=-350, y=400, w=400, h=200,
            color_fondo="rgba(20,184,166,0.10)", color_borde="#14b8a6",
            descripcion="Red de operaciones OSS",
        )
        create_vlan("VLAN-OSS-Acceso", -430, 420, z_oss, vlan_id=100, red_tipo="interna", network="192.168.100.0")
        create_vlan("VLAN-OSS-Admin", -270, 420, z_oss, vlan_id=101, red_tipo="gestion", network="192.168.101.0")

        z_gercam = create_zone(
            "Zona GERCAM", x=350, y=400, w=400, h=200,
            color_fondo="rgba(249,115,22,0.10)", color_borde="#f97316",
            descripcion="Zona GERCAM - gestion de riesgos y control",
        )
        create_vlan("VLAN-GERCAM", 350, 420, z_gercam, vlan_id=200, red_tipo="interna", network="192.168.200.0")

        for z in [z_dmz_ext, z_dmz_int, z_red_corp, z_serv, z_oss, z_gercam]:
            z.servicio_padre = dc
            z.save()

        self.stdout.write("")
        self.stdout.write("=" * 60)
        self.stdout.write("SUMMARY:")
        total = Servicio.objects.count()
        zones = Servicio.objects.filter(tipo__in=["zona", "datacenter"]).count()
        with_parent = Servicio.objects.exclude(servicio_padre__isnull=True).count()
        self.stdout.write(f"  Total services: {total}")
        self.stdout.write(f"  Zones/Datacenters: {zones}")
        self.stdout.write(f"  With parent assigned: {with_parent}")
        self.stdout.write("=" * 60)
