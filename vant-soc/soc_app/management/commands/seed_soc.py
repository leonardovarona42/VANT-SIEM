#!/usr/bin/env python
"""Seed data for vant-soc: categories, subcategories, measures."""
import os
import sys
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))
sys.path.insert(0, os.path.dirname(__file__))
django.setup()

from soc_app.models import Categoria, Subcategoria, Medida


CATEGORIAS_DATA = [
    {
        "nombre": "Incidentes de Acceso No Autorizado",
        "descripcion": "Acceso a recursos sin autorizacion explotando vulnerabilidades o credenciales comprometidas.",
        "subcategorias": [
            ("Acceso a cuentas de usuario", 8),
            ("Elevacion de privilegios", 9),
            ("Acceso remoto no autorizado", 8),
            ("Bypass de controles de acceso", 7),
        ],
    },
    {
        "nombre": "Incidentes de Malware",
        "descripcion": "Infeccion por software malicioso: virus, troyanos, ransomware, gusanos, spyware.",
        "subcategorias": [
            ("Ransomware", 10),
            ("Troyano bancario", 8),
            ("Gusano de red", 8),
            ("Spyware / Keylogger", 7),
            ("Rootkit", 9),
            ("Minero de criptomonedas", 6),
        ],
    },
    {
        "nombre": "Incidentes de Denegacion de Servicio",
        "descripcion": "Ataques que buscan inhabilitar servicios criticos o degradar su disponibilidad.",
        "subcategorias": [
            ("DDoS volumetrico", 8),
            ("DDoS de aplicacion", 7),
            ("DoS interno", 5),
            ("Agotamiento de recursos", 6),
        ],
    },
    {
        "nombre": "Incidentes de Perdida de Informacion",
        "descripcion": "Filtracion, destruccion o robo de datos sensibles o criticos.",
        "subcategorias": [
            ("Filtracion de datos clasificados", 10),
            ("Destruccion no autorizada de datos", 8),
            ("Robo de dispositivos con datos", 7),
            ("Backup corrupto o inaccesible", 6),
        ],
    },
    {
        "nombre": "Incidentes de Disponibilidad",
        "descripcion": "Fallos que afectan la continuidad operacional de servicios criticos.",
        "subcategorias": [
            ("Fallo de infraestructura critica", 9),
            ("Interrupcion de comunicaciones", 7),
            ("Fallo de servicios esenciales", 8),
        ],
    },
    {
        "nombre": "Incidentes de Integridad",
        "descripcion": "Modificaciones no autorizadas de datos, configuraciones o codigo.",
        "subcategorias": [
            ("Modificacion no autorizada de datos", 8),
            ("Tampering de configuraciones", 7),
            ("Inyeccion de codigo", 9),
            ("Manipulacion de logs", 7),
        ],
    },
    {
        "nombre": "Incidentes de Confidencialidad",
        "descripcion": "Violaciones de la confidencialidad de la informacion.",
        "subcategorias": [
            ("Intercepcion de comunicaciones", 8),
            ("Vazamiento de credenciales", 8),
            ("Exposicion de datos en servidores web", 7),
            ("Acceso no autorizado a bases de datos", 9),
        ],
    },
    {
        "nombre": "Incidentes de Vulnerabilidades",
        "descripcion": "Deteccion y explotacion de debilidades en sistemas y aplicaciones.",
        "subcategorias": [
            ("Vulnerabilidad critica sin parche", 9),
            ("Explotacion de zero-day", 10),
            ("Configuracion insegura", 6),
            ("Servicios expuestos innecesariamente", 5),
        ],
    },
    {
        "nombre": "Incidentes de Ingenieria Social",
        "descripcion": "Manipulacion psicologica para obtener acceso o informacion confidencial.",
        "subcategorias": [
            ("Phishing / Spear phishing", 8),
            ("Vishing / Smishing", 7),
            ("Pretexting", 6),
            ("Baiting", 5),
            ("Watering hole", 7),
        ],
    },
    {
        "nombre": "Incidentes de Ataques a la Cadena de Suministro",
        "descripcion": "Compromiso de software, hardware o servicios de proveedores externos.",
        "subcategorias": [
            ("Software comprometido de proveedor", 9),
            ("Hardware con backdoor", 8),
            ("Servicio cloud comprometido", 8),
            ("Dependencia vulnerable (Log4j, etc.)", 7),
        ],
    },
]

MEDIDAS_DATA = [
    ("Bloqueo de IP /Direccion", "Bloquear la direccion IP o rango de IPs identificadas como origen del ataque."),
    ("Cambio de contrasenas", "Restablecer contrasenas de cuentas comprometidas o en riesgo."),
    ("Analisis forense", "Evaluacion tecnica profunda para determinar alcance y origen del incidente."),
    ("Notificacion a autoridades", "Comunicar el incidente a las autoridades competentes segun la normativa."),
    ("Restauracion de backups", "Recuperar datos desde copias de seguridad conocidas como seguras."),
    ("Aislamiento de sistemas", "Desconectar sistemas comprometidos de la red para contener el daño."),
    ("Actualizacion de parches", "Aplicar actualizaciones de seguridad pendientes en sistemas afectados."),
    ("Refuerzo de firewall", "Modificar reglas de firewall para bloquear vectores de ataque."),
    ("Monitoreo intensivo", "Aumentar la frecuencia y profundidad del monitoreo en sistemas criticos."),
    ("Revision de permisos", "Auditar y ajustar permisos de acceso en todos los sistemas relacionados."),
    ("Implementacion de MFA", "Activar autenticacion multifactor en cuentas y servicios criticos."),
    ("Segmentacion de red", "Reconfigurar la red para aislar segmentos y limitar el movimiento lateral."),
    ("Capacitacion al personal", "Entrenar a los empleados sobre el tipo de incidente detectado."),
    ("Comunicacion interna", "Informar a las partes interesadas sobre el estado del incidente."),
    ("Documentacion del incidente", "Registrar todas las acciones tomadas y hallazgos para referencia futura."),
    ("Prueba de penetracion", "Realizar pruebas de penetracion para validar la efectividad de las medidas."),
    ("Revocacion de credenciales", "Invalidar tokens, sesiones y credenciales comprometidas."),
    ("Contencion de malware", "Eliminar artefactos de malware y verificar la limpieza de sistemas."),
]


def seed():
    print("Seeding categorias...")
    for cat_data in CATEGORIAS_DATA:
        cat, created = Categoria.objects.get_or_create(
            nombre=cat_data["nombre"],
            defaults={"descripcion": cat_data["descripcion"]},
        )
        if created:
            print(f"  + {cat.nombre}")
        for sub_name, nivel in cat_data["subcategorias"]:
            sub, created = Subcategoria.objects.get_or_create(
                categoria=cat,
                nombre=sub_name,
                defaults={"nivel_peligrosidad": nivel, "descripcion": ""},
            )
            if created:
                print(f"    + {sub.nombre} (peligro: {nivel})")

    print("\nSeeding medidas...")
    for nombre, desc in MEDIDAS_DATA:
        med, created = Medida.objects.get_or_create(
            nombre=nombre,
            defaults={"descripcion": desc},
        )
        if created:
            print(f"  + {med.nombre}")

    print("\nDone!")


if __name__ == "__main__":
    seed()
