"""
Script para programar la rotación automática de logs de Suricata
Este script puede ser ejecutado por cron cada 5 horas
"""
import os
import sys
import django
from pathlib import Path

# Configurar Django
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
sys.path.append(str(BASE_DIR))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CORE.settings')
django.setup()

from django.core.management import call_command
from django.utils import timezone
import logging

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/vant-siem/log-rotation.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def main():
    """Función principal para rotar logs"""
    try:
        logger.info("🔄 Iniciando rotación automática de logs de Suricata")
        
        # Ejecutar comando de rotación con backup
        call_command(
            'rotate_suricata_logs',
            backup=True,
            hours=5,
            verbosity=2
        )
        
        logger.info("✅ Rotación de logs completada exitosamente")
        
    except Exception as e:
        logger.error(f"❌ Error en rotación de logs: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
