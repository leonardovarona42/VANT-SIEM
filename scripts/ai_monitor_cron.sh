#!/bin/bash

# Script para ejecutar monitoreo automático de alertas con IA cada 5 minutos
# Configurar en crontab: */5 * * * * /path/to/ai_monitor_cron.sh

# Configuración
PROJECT_PATH="/c/Users/leonardo.varona/3D Objects/develop/CORE"
VENV_PATH="$PROJECT_PATH/venv"  # Ajustar según tu entorno virtual
PYTHON_PATH="$VENV_PATH/bin/python"
MANAGE_PY="$PROJECT_PATH/manage.py"

# Log del script
LOG_FILE="$PROJECT_PATH/logs/ai_monitor.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$TIMESTAMP] Iniciando monitoreo automático de alertas..." >> "$LOG_FILE"

# Cambiar al directorio del proyecto
cd "$PROJECT_PATH" || {
    echo "[$TIMESTAMP] ERROR: No se pudo cambiar al directorio $PROJECT_PATH" >> "$LOG_FILE"
    exit 1
}

# Activar entorno virtual si existe
if [ -f "$VENV_PATH/bin/activate" ]; then
    source "$VENV_PATH/bin/activate"
    echo "[$TIMESTAMP] Entorno virtual activado" >> "$LOG_FILE"
fi

# Ejecutar el comando de monitoreo
"$PYTHON_PATH" "$MANAGE_PY" ai_alert_monitor >> "$LOG_FILE" 2>&1

# Verificar el código de salida
EXIT_CODE=$?
if [ $EXIT_CODE -eq 0 ]; then
    echo "[$TIMESTAMP] Monitoreo completado exitosamente" >> "$LOG_FILE"
else
    echo "[$TIMESTAMP] ERROR: Monitoreo falló con código $EXIT_CODE" >> "$LOG_FILE"
fi

echo "[$TIMESTAMP] Fin del monitoreo automático" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"