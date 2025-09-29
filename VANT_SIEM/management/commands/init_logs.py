from django.core.management.base import BaseCommand
import os
import json
from django.conf import settings
from VANT_SIEM.logging_system import event_logger

class Command(BaseCommand):
    help = 'Inicializar el sistema de logs de VANT-SIEM'

    def handle(self, *args, **options):
        # Crear directorio de logs si no existe
        logs_dir = os.path.join(settings.BASE_DIR, 'logs')
        os.makedirs(logs_dir, exist_ok=True)
        
        # Crear archivo de logs inicial
        logs_file = os.path.join(logs_dir, 'eventos.json')
        
        try:
            # Verificar si el archivo existe y es válido
            if os.path.exists(logs_file):
                with open(logs_file, 'r', encoding='utf-8') as f:
                    json.load(f)
                self.stdout.write(
                    self.style.SUCCESS('Archivo de logs ya existe y es válido')
                )
            else:
                # Crear archivo vacío
                with open(logs_file, 'w', encoding='utf-8') as f:
                    json.dump([], f, ensure_ascii=False, indent=2)
                self.stdout.write(
                    self.style.SUCCESS('Archivo de logs creado exitosamente')
                )
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Si hay error, recrear el archivo
            with open(logs_file, 'w', encoding='utf-8') as f:
                json.dump([], f, ensure_ascii=False, indent=2)
            self.stdout.write(
                self.style.WARNING('Archivo de logs corregido (había errores de codificación)')
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error al inicializar logs: {e}')
            )
            return
        
        # Verificar estado del sistema de logging
        self.stdout.write(
            self.style.SUCCESS('Sistema de logs inicializado correctamente')
        )
        
        # Mostrar estado del sistema
        if event_logger.is_enabled:
            self.stdout.write(
                self.style.SUCCESS('✅ Sistema de logging: ACTIVO')
            )
        else:
            self.stdout.write(
                self.style.WARNING('⚠️  Sistema de logging: DETENIDO')
            )
        
        self.stdout.write(
            self.style.SUCCESS('🎯 El sistema se inicia automáticamente al arrancar la aplicación')
        )
        self.stdout.write(
            self.style.SUCCESS('🔧 Solo los superusuarios pueden controlar el sistema desde la interfaz')
        )
