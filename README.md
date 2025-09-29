# VANT-SIEM CORE

## Sistema de Gestión de Información y Eventos de Seguridad (SIEM)

VANT-SIEM CORE es una plataforma integral de SIEM (Security Information and Event Management) desarrollada en Django que proporciona gestión completa de incidentes de seguridad, análisis de logs IDS/IPS, monitoreo de servicios, y herramientas avanzadas de análisis de amenazas.

## 🚀 Características Principales

### 📊 Gestión de Incidentes (EVENT_M)

- **Reportes de Seguridad**: Sistema completo para reportar incidentes con categorización y priorización
- **Gestión de Incidentes**: Seguimiento del ciclo de vida completo de incidentes de seguridad
- **Categorización Jerárquica**: Categorias, subcategorias y niveles de peligrosidad
- **Gestión de Responsables**: Asignación de responsabilidades por área y rol
- **Monitoreo de Servicios**: Monitoreo automático de disponibilidad y latencia de servicios críticos
- **Medidas Correctivas**: Seguimiento de medidas implementadas y cumplimiento

### 🔍 Análisis IDS/IPS (ids_ingest)

- **Soporte Multi-IDS**: Compatibilidad completa con Snort 2.9/3.0 y Suricata
- **Ingesta en Tiempo Real**: Procesamiento automático de logs con seguimiento de posición
- **Parsers Avanzados**: Soporte para múltiples formatos de log (estándar, JSON, syslog)
- **Dashboards Interactivos**: Visualización en tiempo real con filtros avanzados
- **Sistema de Alertas**: Generación automática de alertas críticas con reconocimiento
- **Estadísticas Detalladas**: Métricas de rendimiento y tendencias temporales
- **Deduplicación Inteligente**: Prevención de registros duplicados con hash único

### 🛡️ Sistema SIEM Principal (VANT_SIEM)

- **Gestión de Usuarios**: Sistema de aprobación y permisos granulares
- **Sistema de Notificaciones Mejorado**: Múltiples canales (Email, SMS, Slack, Teams, Webhooks, Push)
- **Procesamiento Asíncrono**: Cola de notificaciones con reintentos automáticos
- **Plantillas Personalizables**: Sistema de templates para diferentes tipos de eventos
- **Logging Avanzado**: Registro completo de actividades con auditoría
- **Alertas por Correo**: Configuración flexible de alertas automáticas
- **APIs de Análisis**: Integración con VirusTotal, AbuseIPDB y MacVendors
- **Análisis Inteligente con IA**: Integración con Ollama para análisis predictivo y correlación de amenazas
- **Interfaz Profesional**: Dashboard moderno con tema oscuro

### 📈 Monitoreo y Análisis

- **Dashboards en Tiempo Real**: Visualización de métricas y estadísticas
- **Análisis de Amenazas**: Correlación de eventos y patrones de ataque
- **Reportes Automatizados**: Generación de reportes de seguridad
- **Auditoría Completa**: Trazabilidad de todas las operaciones

### 🤖 Análisis Inteligente con IA (Ollama)

- **Análisis Predictivo**: Predicción de tendencias de amenazas usando IA
- **Correlación Inteligente**: Análisis de eventos entre Snort y Suricata
- **Análisis de Comportamiento IP**: Evaluación de amenazas por dirección IP
- **Generación de Reportes**: Reportes ejecutivos automáticos con insights de IA
- **Alertas Inteligentes**: Notificaciones por correo basadas en análisis de IA
- **Cruzado de Información**: Consulta inteligente en toda la base de datos
- **Análisis de Logs Ingestados**: Procesamiento inteligente de logs IDS/IPS

### 🔔 Sistema de Notificaciones Avanzado

- **Múltiples Canales**: Email, SMS, Slack, Microsoft Teams, Webhooks, Push Notifications
- **Procesamiento Asíncrono**: Cola de notificaciones con worker dedicado
- **Plantillas Personalizables**: Templates para diferentes tipos de eventos
- **Reintentos Automáticos**: Sistema robusto con manejo de fallos
- **Limpieza Automática**: Gestión automática de notificaciones antiguas
- **Configuración Centralizada**: Interfaz web para gestión completa

## 🏗️ Arquitectura del Sistema

```
VANT-SIEM CORE/
├── CORE/                 # Proyecto Django principal
├── EVENT_M/             # Módulo de gestión de incidentes
├── VANT_SIEM/          # Núcleo del SIEM
├── ids_ingest/         # Servicio de ingesta IDS/IPS
├── staticfiles/        # Archivos estáticos
├── logs/               # Logs del sistema
├── scripts/            # Scripts de automatización
└── evidencias/         # Almacenamiento de evidencias
```

## 📋 Requisitos del Sistema

- **Python**: 3.10+
- **Django**: 5.0+
- **Base de Datos**: PostgreSQL
- **Servidores IDS**: Snort 2.9/3.0 o Suricata (opcional)
- **IA Local**: Ollama con modelo llama3.2 (opcional pero recomendado)
- **Sistema Operativo**: Linux/Windows con soporte para Django

## 🚀 Instalación y Configuración

### 1. Clonación del Repositorio

```bash
git clone https://github.com/leonardovarona42/VANT-SIEM.git
cd VANT-SIEM-CORE
```

### 2. Instalación de Dependencias

```bash
pip install -r requirements.txt
```

### 3. Configuración de Base de Datos

```bash
# Configurar PostgreSQL en CORE/settings.py
python manage.py makemigrations
python manage.py migrate
```

### 4. Creación de Superusuario

```bash
python manage.py createsuperuser
```

### 5. Inicio del Servidor

```bash
python manage.py runserver
```

## 🔧 Configuración Avanzada

### Configuración IDS/IPS

1. Acceder a `/ids-ingest/config/`
2. Crear configuración para Snort o Suricata
3. Configurar rutas de archivos de log
4. Activar ingesta automática

### Configuración de APIs de Análisis

1. Obtener claves API de VirusTotal, AbuseIPDB, MacVendors
2. Configurar en `/analysis/config/`
3. Activar servicios de análisis

### Configuración de Correo

1. Configurar servidor SMTP en `/email/config/`
2. Crear plantillas de alertas
3. Configurar destinatarios

### Configuración de Ollama (IA)

1. Instalar Ollama localmente: `https://ollama.ai/`
2. Descargar modelo: `ollama pull llama3.2`
3. Iniciar servicio: `ollama serve`
4. Verificar conexión en `/analysis/ollama/test/`
5. Configurar análisis automático en dashboards

## 📖 Uso del Sistema

### Acceso al Sistema

- **URL Principal**: `http://localhost:8000/siem/`
- **Login**: `/siem/login/`
- **Dashboard**: `/siem/dashboard/`

### Dashboards Disponibles

- **Dashboard General**: `/siem/dashboard/` - Vista general del sistema
- **Amenazas IDS**: `/siem/dashboard/threats/` - Eventos de seguridad
- **Snort**: `/ids-ingest/snort/` - Dashboard específico de Snort
- **Suricata**: `/ids-ingest/suricata/` - Dashboard específico de Suricata
- **Análisis IA**: `/analysis/ollama/` - Análisis inteligente con Ollama
- **Reportes IA**: `/analysis/ollama/reports/` - Reportes generados por IA

### Gestión de Incidentes

- **Reportes**: `/event-m/reports/` - Crear y gestionar reportes
- **Incidentes**: `/event-m/incidents/` - Gestión del ciclo de vida de incidentes
- **Monitoreo**: `/event-m/monitoring/` - Estado de servicios
- **Reportes Externos**: `/eventos/reporte_externo/` - Formulario público sin autenticación

## 🔐 Seguridad y Permisos

### Niveles de Usuario

- **Superusuario**: Control total del sistema
- **Administrador**: Gestión de usuarios y configuraciones
- **Analista**: Acceso a dashboards y reportes
- **Usuario Básico**: Acceso limitado según permisos

### Permisos Granulares

- Visualización de reportes/incidentes
- Creación y edición de contenido
- Gestión de usuarios y permisos
- Acceso a configuraciones del sistema

## 📊 Monitoreo y Mantenimiento

### Comandos de Gestión

```bash
# Ingesta IDS
python manage.py ingest_ids_logs

# Rotación de logs
python manage.py rotate_suricata_logs

# Limpieza de datos antiguos
python manage.py cleanup_old_logs

# Monitoreo de servicios
python manage.py monitor_services
```

### Logs del Sistema

- **Aplicación**: `logs/django.log`
- **IDS**: `logs/ids_ingest.log`
- **Eventos**: `logs/eventos.json`

## 🔗 APIs y Integraciones

### Endpoints REST

- `/api/notifications/` - Gestión de notificaciones
- `/api/alerts/` - Alertas del sistema
- `/api/analysis/` - Servicios de análisis
- `/api/ollama/` - Servicios de IA con Ollama
- `/ids-ingest/api/` - Datos IDS/IPS

### Webhooks

- Notificaciones automáticas
- Integración con herramientas externas
- Alertas en tiempo real

## 📚 Documentación

- **[Manual de Usuario](USER_MANUAL.md)**: Guía completa para usuarios finales
- **[Arquitectura y Diagramas](ARCHITECTURE.md)**: Diagramas de flujo y arquitectura del sistema
- **[Registro de Cambios](CHANGELOG.md)**: Historial completo de mejoras y versiones
- **[Sistema de Logging](SISTEMA_LOGGING_README.md)**: Documentación del sistema de auditoría
- **[Gestión de Usuarios](SISTEMA_USUARIOS_README.md)**: Sistema de usuarios y permisos
- **[Servicio IDS](ids_ingest/README.md)**: Documentación detallada del módulo IDS/IPS

### 📁 Documentación Archivada

Documentos de desarrollo específicos se encuentran en `docs/archive/` para referencia histórica.

## 🤝 Contribución

1. Fork el proyecto
2. Crear rama para nueva funcionalidad (`git checkout -b feature/nueva-funcionalidad`)
3. Commit cambios (`git commit -am 'Agrega nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Crear Pull Request

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Ver archivo `LICENSE` para más detalles.

## 🆘 Soporte

Para soporte técnico o reportes de bugs:

- Crear issue en el repositorio
- Contactar al equipo de desarrollo
- Consultar la documentación completa

---

**VANT-SIEM CORE** - Plataforma integral para la gestión y análisis de seguridad de la información.
