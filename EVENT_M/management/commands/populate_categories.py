from django.core.management.base import BaseCommand
from EVENT_M.models import Categoria, Subcategoria

class Command(BaseCommand):
    help = 'Poblar categorías y subcategorías según la Resolución 105/2021 Modelo de actuación nacional ante incidentes de ciberseguridad de Cuba'

    def handle(self, *args, **options):
        # Datos de categorías y subcategorías basados en la Resolución 105/2021
        categorias_data = [
            {
                'nombre': 'Incidentes de Acceso No Autorizado',
                'descripcion': 'Incidentes relacionados con accesos no autorizados a sistemas o información',
                'subcategorias': [
                    {'nombre': 'Acceso físico no autorizado', 'descripcion': 'Acceso no autorizado a instalaciones físicas', 'nivel': 6},
                    {'nombre': 'Acceso remoto no autorizado', 'descripcion': 'Acceso no autorizado a través de redes', 'nivel': 7},
                    {'nombre': 'Uso de credenciales comprometidas', 'descripcion': 'Uso de credenciales robadas o comprometidas', 'nivel': 8},
                ]
            },
            {
                'nombre': 'Incidentes de Malware',
                'descripcion': 'Incidentes causados por software malicioso',
                'subcategorias': [
                    {'nombre': 'Virus', 'descripcion': 'Programas que se replican infectando otros archivos', 'nivel': 7},
                    {'nombre': 'Gusanos', 'descripcion': 'Malware que se propaga sin intervención del usuario', 'nivel': 8},
                    {'nombre': 'Troyanos', 'descripcion': 'Malware que se disfraza de software legítimo', 'nivel': 9},
                    {'nombre': 'Ransomware', 'descripcion': 'Malware que encripta datos y exige rescate', 'nivel': 10},
                    {'nombre': 'Spyware', 'descripcion': 'Malware que espía actividades del usuario', 'nivel': 6},
                    {'nombre': 'Adware', 'descripcion': 'Malware que muestra publicidad no deseada', 'nivel': 4},
                ]
            },
            {
                'nombre': 'Incidentes de Denegación de Servicio',
                'descripcion': 'Incidentes que impiden el acceso a servicios',
                'subcategorias': [
                    {'nombre': 'DoS', 'descripcion': 'Ataque de denegación de servicio desde una fuente', 'nivel': 8},
                    {'nombre': 'DDoS', 'descripcion': 'Ataque de denegación de servicio distribuido', 'nivel': 9},
                    {'nombre': 'DoS de aplicación', 'descripcion': 'Ataque que sobrecarga aplicaciones específicas', 'nivel': 7},
                ]
            },
            {
                'nombre': 'Incidentes de Pérdida de Información',
                'descripcion': 'Incidentes que resultan en pérdida de datos',
                'subcategorias': [
                    {'nombre': 'Pérdida accidental', 'descripcion': 'Pérdida de datos por error humano', 'nivel': 5},
                    {'nombre': 'Pérdida por robo', 'descripcion': 'Pérdida de datos debido a robo físico', 'nivel': 8},
                    {'nombre': 'Pérdida por eliminación', 'descripcion': 'Eliminación accidental o intencional de datos', 'nivel': 6},
                ]
            },
            {
                'nombre': 'Incidentes de Disponibilidad',
                'descripcion': 'Incidentes que afectan la disponibilidad de sistemas',
                'subcategorias': [
                    {'nombre': 'Falla de hardware', 'descripcion': 'Indisponibilidad por fallos en hardware', 'nivel': 4},
                    {'nombre': 'Falla de software', 'descripcion': 'Indisponibilidad por fallos en software', 'nivel': 5},
                    {'nombre': 'Sobrecarga de recursos', 'descripcion': 'Indisponibilidad por uso excesivo de recursos', 'nivel': 6},
                ]
            },
            {
                'nombre': 'Incidentes de Integridad',
                'descripcion': 'Incidentes que comprometen la integridad de la información',
                'subcategorias': [
                    {'nombre': 'Modificación no autorizada', 'descripcion': 'Alteración de datos sin autorización', 'nivel': 8},
                    {'nombre': 'Corrupción de datos', 'descripcion': 'Daño en la integridad de los datos', 'nivel': 7},
                    {'nombre': 'Manipulación de logs', 'descripcion': 'Alteración de registros de auditoría', 'nivel': 9},
                ]
            },
            {
                'nombre': 'Incidentes de Confidencialidad',
                'descripcion': 'Incidentes que comprometen la confidencialidad de la información',
                'subcategorias': [
                    {'nombre': 'Divulgación no autorizada', 'descripcion': 'Revelación de información confidencial', 'nivel': 9},
                    {'nombre': 'Intercepción de comunicaciones', 'descripcion': 'Captura de datos en tránsito', 'nivel': 8},
                    {'nombre': 'Fuga de datos', 'descripcion': 'Pérdida de control sobre información sensible', 'nivel': 10},
                ]
            },
            {
                'nombre': 'Incidentes de Vulnerabilidades',
                'descripcion': 'Incidentes relacionados con vulnerabilidades de seguridad',
                'subcategorias': [
                    {'nombre': 'Vulnerabilidades conocidas', 'descripcion': 'Explotación de vulnerabilidades públicas', 'nivel': 7},
                    {'nombre': 'Vulnerabilidades zero-day', 'descripcion': 'Explotación de vulnerabilidades desconocidas', 'nivel': 10},
                    {'nombre': 'Configuración insegura', 'descripcion': 'Problemas por configuraciones inadecuadas', 'nivel': 5},
                ]
            },
            {
                'nombre': 'Incidentes de Ingeniería Social',
                'descripcion': 'Incidentes basados en manipulación humana',
                'subcategorias': [
                    {'nombre': 'Phishing', 'descripcion': 'Ataques que engañan para obtener información', 'nivel': 7},
                    {'nombre': 'Vishing', 'descripcion': 'Phishing por voz telefónica', 'nivel': 6},
                    {'nombre': 'Smishing', 'descripcion': 'Phishing por mensajes SMS', 'nivel': 6},
                    {'nombre': 'Baiting', 'descripcion': 'Ataques con cebo físico o digital', 'nivel': 5},
                ]
            },
            {
                'nombre': 'Incidentes de Ataques a la Cadena de Suministro',
                'descripcion': 'Incidentes que afectan la cadena de suministro de software',
                'subcategorias': [
                    {'nombre': 'Compromiso de proveedores', 'descripcion': 'Ataques a proveedores de software', 'nivel': 9},
                    {'nombre': 'Software malicioso en actualizaciones', 'descripcion': 'Malware introducido en actualizaciones', 'nivel': 10},
                    {'nombre': 'Dependencias comprometidas', 'descripcion': 'Librerías o componentes vulnerables', 'nivel': 8},
                ]
            },
        ]

        for cat_data in categorias_data:
            categoria, created = Categoria.objects.get_or_create(
                nombre=cat_data['nombre'],
                defaults={'descripcion': cat_data['descripcion']}
            )
            if created:
                self.stdout.write(f'Creada categoría: {categoria.nombre}')
            else:
                self.stdout.write(f'Categoría ya existe: {categoria.nombre}')

            for sub_data in cat_data['subcategorias']:
                subcategoria, sub_created = Subcategoria.objects.get_or_create(
                    nombre=sub_data['nombre'],
                    categoria=categoria,
                    defaults={
                        'descripcion': sub_data['descripcion'],
                        'nivel_peligrosidad': sub_data['nivel']
                    }
                )
                if sub_created:
                    self.stdout.write(f'  Creada subcategoría: {subcategoria.nombre}')
                else:
                    self.stdout.write(f'  Subcategoría ya existe: {subcategoria.nombre}')

        self.stdout.write(self.style.SUCCESS('Población de categorías y subcategorías completada'))