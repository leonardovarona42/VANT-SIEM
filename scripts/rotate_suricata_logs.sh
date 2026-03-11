#!/bin/bash

# Script para rotar logs de Suricata cada 5 horas
# Uso: Agregar a crontab: 0 */5 * * * /path/to/scripts/rotate_suricata_logs.sh

# Configuración
PROJECT_DIR="/path/to/your/CORE"  # Cambiar por la ruta real del proyecto
LOG_DIR="/var/log/vant-siem"
PYTHON_PATH="/usr/bin/python3"  # Ajustar según tu instalación

# Crear directorio de logs si no existe
mkdir -p "$LOG_DIR"

# Cambiar al directorio del proyecto
cd "$PROJECT_DIR"

# Activar entorno virtual si existe
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

# Ejecutar rotación de logs
echo "$(date): Iniciando rotación de logs de Suricata" >> "$LOG_DIR/rotation.log"

$PYTHON_PATH manage.py rotate_suricata_logs --backup --hours=5 >> "$LOG_DIR/rotation.log" 2>&1

if [ $? -eq 0 ]; then
    echo "$(date): Rotación completada exitosamente" >> "$LOG_DIR/rotation.log"
else
    echo "$(date): Error en la rotación de logs" >> "$LOG_DIR/rotation.log"
    exit 1
fi
