# Rotación de Logs de Suricata

## Descripción

Este sistema implementa una rotación automática de archivos de log de Suricata que elimina el contenido ya ingerido de los archivos originales cada 5 horas, manteniendo los archivos pero vaciándolos para evitar que crezcan indefinidamente.

## Características

- **Rotación automática**: Elimina contenido ya ingerido de archivos de log
- **Backup automático**: Crea copias de seguridad antes de rotar
- **Configuración flexible**: Permite ajustar el intervalo de rotación
- **Logging detallado**: Registra todas las operaciones
- **Modo dry-run**: Permite simular la rotación sin ejecutarla

## Archivos Implementados

### 1. Comando de Rotación
- **Archivo**: `ids_ingest/management/commands/rotate_suricata_logs.py`
- **Uso**: `python manage.py rotate_suricata_logs [opciones]`

### 2. Script de Programación
- **Archivo**: `ids_ingest/management/commands/schedule_log_rotation.py`
- **Uso**: Ejecutar desde cron o como servicio

### 3. Script Shell para Cron
- **Archivo**: `scripts/rotate_suricata_logs.sh`
- **Uso**: Agregar a crontab para ejecución automática

## Uso

### Rotación Manual

```bash
# Rotación básica
python manage.py rotate_suricata_logs

# Con backup
python manage.py rotate_suricata_logs --backup

# Simulación (dry-run)
python manage.py rotate_suricata_logs --dry-run

# Con intervalo personalizado
python manage.py rotate_suricata_logs --hours=3
```

### Configuración Automática con Cron

1. **Editar el script shell**:
   ```bash
   nano scripts/rotate_suricata_logs.sh
   ```
   
   Cambiar las variables:
   ```bash
   PROJECT_DIR="/ruta/real/a/tu/proyecto/CORE"
   PYTHON_PATH="/usr/bin/python3"  # o la ruta correcta
   ```

2. **Hacer ejecutable**:
   ```bash
   chmod +x scripts/rotate_suricata_logs.sh
   ```

3. **Agregar a crontab**:
   ```bash
   crontab -e
   ```
   
   Agregar la línea:
   ```bash
   # Rotar logs de Suricata cada 5 horas
   0 */5 * * * /ruta/completa/a/scripts/rotate_suricata_logs.sh
   ```

### Configuración como Servicio Systemd

Crear archivo de servicio:

```bash
sudo nano /etc/systemd/system/suricata-log-rotation.service
```

Contenido:
```ini
[Unit]
Description=Suricata Log Rotation Service
After=network.target

[Service]
Type=oneshot
User=www-data
Group=www-data
WorkingDirectory=/ruta/a/tu/proyecto/CORE
ExecStart=/usr/bin/python3 manage.py rotate_suricata_logs --backup --hours=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Crear timer:

```bash
sudo nano /etc/systemd/system/suricata-log-rotation.timer
```

Contenido:
```ini
[Unit]
Description=Run Suricata Log Rotation every 5 hours
Requires=suricata-log-rotation.service

[Timer]
OnCalendar=*-*-* 00,05,10,15,20:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

Activar:
```bash
sudo systemctl enable suricata-log-rotation.timer
sudo systemctl start suricata-log-rotation.timer
```

## Archivos que se Rotan

El sistema rota los siguientes archivos de log de Suricata:

- `eve.json` - Eventos en formato JSON
- `fast.log` - Alertas rápidas
- `stats.log` - Estadísticas del motor
- `suricata.log` - Logs del sistema

## Configuración

### Variables de Entorno

```bash
# Directorio de logs del sistema
export VANT_SIEM_LOG_DIR="/var/log/vant-siem"

# Intervalo de rotación (horas)
export LOG_ROTATION_HOURS=5
```

### Configuración en Django

En `settings.py`:

```python
# Configuración de rotación de logs
LOG_ROTATION_CONFIG = {
    'BACKUP_ENABLED': True,
    'RETENTION_HOURS': 5,
    'LOG_DIR': '/var/log/vant-siem',
    'BACKUP_DIR': '/var/log/vant-siem/backups'
}
```

## Monitoreo

### Logs del Sistema

Los logs de rotación se guardan en:
- `/var/log/vant-siem/rotation.log` - Log principal
- `/var/log/vant-siem/log-rotation.log` - Log detallado

### Verificar Estado

```bash
# Ver logs recientes
tail -f /var/log/vant-siem/rotation.log

# Verificar configuración de cron
crontab -l

# Verificar servicio systemd
systemctl status suricata-log-rotation.timer
```

## Seguridad

- Los archivos de backup se crean con permisos restrictivos
- Solo el usuario del servicio web puede ejecutar la rotación
- Los logs se rotan de forma segura sin pérdida de datos

## Troubleshooting

### Problemas Comunes

1. **Permisos insuficientes**:
   ```bash
   sudo chown -R www-data:www-data /var/log/vant-siem
   sudo chmod -R 755 /var/log/vant-siem
   ```

2. **Ruta del proyecto incorrecta**:
   - Verificar la variable `PROJECT_DIR` en el script
   - Asegurar que la ruta sea absoluta

3. **Python no encontrado**:
   - Verificar la variable `PYTHON_PATH`
   - Usar `which python3` para encontrar la ruta correcta

### Logs de Debug

```bash
# Ejecutar con verbosidad alta
python manage.py rotate_suricata_logs --verbosity=3

# Ver logs de Django
tail -f /var/log/django.log
```

## Integración con el Sistema de Ingesta

La rotación se integra automáticamente con el sistema de ingesta:

1. **Antes de la rotación**: Se verifica que la ingesta haya procesado los logs
2. **Durante la rotación**: Se crean backups y se truncan los archivos
3. **Después de la rotación**: Se reinicia la posición de lectura para nuevos logs

## Consideraciones de Rendimiento

- La rotación se ejecuta durante horas de menor actividad
- Los backups se crean de forma eficiente
- El truncado de archivos es instantáneo
- No afecta el rendimiento del sistema de ingesta
