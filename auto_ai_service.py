#!/usr/bin/env python3
"""
Servicio automático de análisis de IA IRIS
Ejecuta análisis cada intervalo configurado usando APScheduler
"""
import os
import sys
import logging
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.interval import IntervalTrigger

# Setup Django
sys.path.append('.')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CORE.settings')

import django
django.setup()

from django.core.management import call_command
from IRIS.models import AIConfiguration

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/auto_ai_service.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def run_auto_analysis():
    """Ejecuta el análisis automático usando el comando de management"""
    try:
        logger.info("Ejecutando análisis automático de IA...")
        call_command('auto_ai_analysis', once=True)
        logger.info("Análisis automático completado")
    except Exception as e:
        logger.error(f"Error en análisis automático: {str(e)}")

def get_analysis_interval():
    """Obtiene el intervalo de análisis desde la configuración"""
    try:
        config = AIConfiguration.objects.first()
        if config and config.auto_analysis_enabled:
            # Convertir horas a segundos
            return config.analysis_interval_hours * 3600
        else:
            logger.warning("Análisis automático desactivado en configuración")
            return None
    except Exception as e:
        logger.error(f"Error obteniendo configuración: {str(e)}")
        return 300  # 5 minutos por defecto

def main():
    """Función principal del servicio"""
    logger.info("Iniciando servicio automático de análisis de IA IRIS...")

    # Verificar configuración inicial
    interval_seconds = get_analysis_interval()
    if not interval_seconds:
        logger.error("Análisis automático está desactivado. Saliendo...")
        return

    logger.info(f"Intervalo de análisis configurado: {interval_seconds} segundos ({interval_seconds/3600:.1f} horas)")

    # Crear scheduler
    scheduler = BlockingScheduler()

    # Agregar job de análisis automático
    trigger = IntervalTrigger(seconds=interval_seconds)
    scheduler.add_job(
        run_auto_analysis,
        trigger=trigger,
        id='auto_ai_analysis',
        name='Análisis Automático IRIS',
        max_instances=1,  # Solo una instancia a la vez
        replace_existing=True
    )

    logger.info("Servicio iniciado. Esperando análisis programados...")

    try:
        # Ejecutar análisis inicial inmediatamente
        run_auto_analysis()

        # Iniciar scheduler
        scheduler.start()

    except KeyboardInterrupt:
        logger.info("Servicio detenido por el usuario")
        scheduler.shutdown()
    except Exception as e:
        logger.error(f"Error en el servicio: {str(e)}")
        scheduler.shutdown()

if __name__ == "__main__":
    main()