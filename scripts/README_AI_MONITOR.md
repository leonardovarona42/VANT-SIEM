# Monitoreo Automático de Alertas con IA

Este sistema permite que la IA revise automáticamente las alertas de Snort y Suricata cada 5 minutos y genere reportes inteligentes.

## 🚀 Funcionalidades

- **Monitoreo continuo**: Revisa alertas cada 5 minutos
- **Análisis inteligente**: Usa Ollama para analizar patrones y amenazas
- **Reportes automáticos**: Genera reportes detallados en el área "Vigilance-Neutralization-threads-SIEM-AI-Monitor"
- **Alertas críticas**: Prioriza amenazas de alta severidad
- **Logging completo**: Registra todas las actividades

## 📋 Configuración

### 1. Comando de Management

Se ha creado el comando `ai_alert_monitor` que puedes ejecutar manualmente:

```bash
python manage.py ai_alert_monitor
```

Opciones:
- `--force`: Fuerza la ejecución incluso si no hay alertas nuevas

### 2. Configuración Automática (Cron)

#### En Linux/Mac:
```bash
# Editar crontab
crontab -e

# Agregar esta línea (ajusta la ruta):
*/5 * * * * /path/to/your/project/scripts/ai_monitor_cron.sh
```

#### En Windows (Task Scheduler):
1. Abrir Task Scheduler
2. Crear nueva tarea básica
3. Configurar para que se ejecute cada 5 minutos
4. Acción: Ejecutar programa
5. Programa: `scripts\ai_monitor_windows.bat`
6. Directorio inicial: `C:\path\to\your\project`

O usar el script batch directamente:
```batch
# Ejecutar el script batch
scripts\ai_monitor_windows.bat
```

### 3. Script de Cron (ai_monitor_cron.sh)

El script `scripts/ai_monitor_cron.sh` está configurado para:
- Activar entorno virtual
- Cambiar al directorio del proyecto
- Ejecutar el comando de monitoreo
- Registrar logs en `logs/ai_monitor.log`

## 📊 Qué hace el sistema

### Cada 5 minutos:
1. **Revisa alertas nuevas**:
   - IDS Alerts (últimos 5 min)
   - Snort Logs (últimos 5 min)
   - Suricata Alerts (últimos 5 min)

2. **Si hay alertas**:
   - Prepara datos para análisis de IA
   - Llama a Ollama para análisis inteligente
   - Genera reporte ejecutivo completo
   - Guarda reporte en base de datos

3. **Si no hay alertas**:
   - Registra que no hay actividad nueva
   - Sale silenciosamente

### Contenido del reporte:
- **Resumen Ejecutivo**: Situación general
- **Análisis de Amenazas**: Patrones identificados
- **Alertas Críticas**: Detalles específicos
- **Recomendaciones**: Acciones sugeridas
- **Métricas**: Estadísticas detalladas
- **Datos técnicos**: JSON completo de alertas

## 🔧 Configuración de Ollama

Asegúrate de que Ollama esté ejecutándose:

```bash
# Verificar conexión
curl http://localhost:11434/api/tags

# Si no funciona, iniciar Ollama
ollama serve
```

## 📁 Archivos creados/modificados

- `VANT_SIEM/management/commands/ai_alert_monitor.py` - Comando principal
- `scripts/ai_monitor_cron.sh` - Script para cron
- `logs/ai_monitor.log` - Archivo de logs
- Área "Vigilance-Neutralization-threads-SIEM-AI-Monitor" - Para reportes automáticos

## 📈 Logs y Monitoreo

Los logs se guardan en `logs/ai_monitor.log`:

```
[2025-01-24 10:00:00] Iniciando monitoreo automático de alertas...
[2025-01-24 10:00:01] Encontradas 15 alertas nuevas en los últimos 5 minutos
[2025-01-24 10:00:05] Reporte automático generado exitosamente: ID 123
[2025-01-24 10:00:05] Monitoreo completado exitosamente
```

## ⚠️ Notas importantes

1. **Ollama debe estar ejecutándose** para que funcione el análisis de IA
2. **Si Ollama no está disponible**, se genera un análisis básico
3. **Los reportes se crean automáticamente** en el área "Vigilance-Neutralization-threads-SIEM-AI-Monitor"
4. **No interfiere con el chat de IA** - son sistemas separados
5. **Es seguro ejecutar múltiples veces** - no duplica reportes

## 🧪 Pruebas

Para probar el sistema:

```bash
# Ejecutar una vez (forzado)
python manage.py ai_alert_monitor --force

# Ver logs
tail -f logs/ai_monitor.log

# Ver reportes generados
# Ir a Reportes -> Área: Vigilance-Neutralization-threads-SIEM-AI-Monitor
```

## 🔄 Personalización

Puedes modificar el comportamiento editando:

- `ai_alert_monitor.py`: Lógica de análisis y reportes
- `ai_monitor_cron.sh`: Configuración del script de cron
- Intervalo de tiempo (actualmente 5 minutos)
- Tipos de alertas a monitorear
- Formato de reportes

## 📞 Soporte

Si hay problemas:
1. Verificar que Ollama esté ejecutándose
2. Revisar logs en `logs/ai_monitor.log`
3. Verificar permisos de escritura en la carpeta de logs
4. Asegurarse de que la base de datos esté accesible