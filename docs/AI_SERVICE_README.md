# Servicio IRIS-S.O.A.R

## 🚀 Descripción

El **Servicio Automático de Análisis de IA IRIS** ejecuta análisis de ciberseguridad de forma automática y programada, sin necesidad de intervención manual. Utiliza APScheduler para ejecutar análisis inteligente SOAR completos según la configuración establecida.

## ⚙️ Características

- **Análisis Automático**: Ejecuta análisis cada intervalo configurado (por defecto cada 24 horas)
- **Configurable**: Respeta la configuración del dashboard de IRIS
- **Logging Completo**: Registra todas las actividades en `logs/auto_ai_service.log`
- **Resistente a Fallos**: Continúa funcionando incluso si hay errores temporales
- **SOAR Completo**: Incluye predicción, correlación, respuesta automática y creación de incidentes

## 📋 Requisitos

- Python 3.8+
- Django 5.2+
- APScheduler 3.10+
- Base de datos PostgreSQL configurada
- Modelos de IA entrenados

## 🛠️ Instalación

### 1. Instalar dependencias
```bash
pip install -r requirements.txt
```

### 2. Configurar base de datos
Asegúrate de que la base de datos esté configurada en `CORE/settings.py` y que las migraciones estén aplicadas:
```bash
python manage.py migrate
```

### 3. Entrenar modelos de IA
```bash
python simple_train.py
```

### 4. Configurar análisis automático
En el dashboard de IRIS (`/siem/dashboard/`), ve a la configuración y:
- ✅ Activa "Análisis automático de logs"
- ⚙️ Configura el intervalo deseado (en horas)
- 💾 Guarda la configuración

## 🚀 Uso

### Opción 1: Servicio Automático (Recomendado)
Ejecuta el servicio que se ejecuta indefinidamente:
```bash
# Windows
python auto_ai_service.py

# Linux/Mac
python auto_ai_service.py
```

### Opción 2: Comando Django Manual
Para ejecutar una sola vez o debugging:
```bash
python manage.py auto_ai_analysis --once
```

### Opción 3: Comando con intervalo personalizado
```bash
# Ejecutar cada 10 minutos
python manage.py auto_ai_analysis --interval=600

# Una sola ejecución
python manage.py auto_ai_analysis --once --interval=300
```

## 📊 Funcionamiento

### Ciclo de Análisis SOAR:

1. **⏰ Programación**: El servicio verifica cada X segundos/minutos configurados
2. **🔍 Análisis**: Examina logs de Snort y Suricata de las últimas horas
3. **🧠 IA**: Aplica modelos de Machine Learning para detectar anomalías
4. **🔗 Correlación**: Agrupa eventos relacionados por tiempo/IP/tipo
5. **🎯 Predicción**: Crea predicciones de amenazas con scoring de confianza
6. **📋 Reportes**: Genera reportes detallados de hallazgos
7. **🚨 Incidentes**: Crea incidentes automáticos para amenazas críticas
8. **🛡️ Respuesta**: Aplica medidas de mitigación específicas
9. **📝 Logging**: Registra toda la actividad para auditoría

### Configuración del Intervalo:

El intervalo se configura en **horas** en el dashboard de IRIS:
- **1 hora**: Análisis muy frecuente (recomendado para producción)
- **6 horas**: Análisis frecuente
- **12 horas**: Análisis moderado
- **24 horas**: Análisis diario (por defecto)

## 📁 Archivos de Log

Los logs se guardan en `logs/auto_ai_service.log`:
```
2026-01-03 05:15:00,123 - INFO - Iniciando servicio automático de análisis de IA IRIS...
2026-01-03 05:15:00,456 - INFO - Intervalo de análisis configurado: 86400 segundos (24.0 horas)
2026-01-03 05:15:00,789 - INFO - Ejecutando análisis automático de IA...
2026-01-03 05:15:05,123 - INFO - Análisis completado: 2 predicciones, 1 incidentes - 2026-01-03 05:15:05
```

## 🔧 Configuración Avanzada

### Variables de Entorno
```bash
# Configurar logging level
export LOG_LEVEL=DEBUG

# Configurar archivo de log personalizado
export LOG_FILE=/var/log/vant-siem/ai_service.log
```

### Configuración del Scheduler
El scheduler está configurado para:
- **max_instances=1**: Solo un análisis a la vez
- **replace_existing=True**: Reemplaza jobs existentes
- **Manejo de errores**: Continúa ejecutándose aunque haya fallos

## 🚨 Monitoreo y Troubleshooting

### Verificar estado del servicio
```bash
# Ver logs en tiempo real
tail -f logs/auto_ai_service.log

# Ver procesos en ejecución
ps aux | grep auto_ai_service
```

### Problemas comunes:

#### ❌ "Análisis automático desactivado"
- Ve al dashboard de IRIS y activa "Análisis automático de logs"

#### ❌ "No se encontraron modelos entrenados"
- Ejecuta `python simple_train.py` para entrenar los modelos

#### ❌ "Error de conexión a base de datos"
- Verifica que PostgreSQL esté ejecutándose
- Revisa la configuración en `CORE/settings.py`

#### ❌ "Error en análisis automático"
- Revisa los logs detallados en `logs/auto_ai_service.log`
- Verifica que los modelos estén correctamente guardados

## 🛑 Detención del Servicio

### Windows:
- Presiona `Ctrl+C` en la terminal
- O cierra la ventana del comando

### Linux/Mac:
```bash
# Encontrar PID
ps aux | grep auto_ai_service

# Matar proceso
kill -9 <PID>
```

## 📈 Métricas y Estadísticas

El servicio registra automáticamente:
- **Predicciones generadas** por ciclo
- **Incidentes creados** por ciclo
- **Tiempo de procesamiento** por análisis
- **Tasa de éxito** de análisis
- **Logs procesados** por ciclo

Todas las métricas están disponibles en el dashboard de IRIS bajo "Análisis Recientes".

## 🔒 Seguridad

- El servicio respeta todos los permisos de Django
- Los análisis se ejecutan con el usuario del sistema
- Los logs no contienen información sensible
- Las configuraciones son encriptadas en la base de datos

## 🎯 Recomendaciones de Producción

1. **Ejecutar como servicio del sistema** (systemd/cron/Windows Service)
2. **Monitoreo continuo** de logs y métricas
3. **Backup regular** de modelos entrenados
4. **Configurar alertas** para fallos del servicio
5. **Ajustar intervalo** según carga del sistema (1-6 horas recomendado)

---

