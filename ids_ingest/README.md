# Servicio IDS/IPS - Vigilance & Neutralization threads SIEM

## Descripción

El servicio IDS/IPS de Vigilance & Neutralization threads SIEM proporciona ingesta, procesamiento y análisis de logs de sistemas de detección de intrusiones como Snort y Suricata. Incluye funcionalidades avanzadas de parsing, alertas en tiempo real, dashboards interactivos y estadísticas detalladas.

## Características Principales

### 🔍 Parsers Avanzados
- **Múltiples formatos de Snort**: Soporte para formatos estándar, con puertos, y con clasificación
- **Múltiples formatos de Suricata**: Formato estándar, alternativo y JSON
- **Validación robusta**: Manejo de errores y validación de líneas de log
- **Parsing inteligente**: Extracción automática de IPs, puertos, protocolos y metadatos

### 📊 Dashboards Interactivos
- **Dashboard Snort**: Visualización de eventos con filtros avanzados
- **Dashboard Suricata**: Análisis de eventos con estadísticas en tiempo real
- **Dashboard de Alertas**: Gestión de alertas críticas con reconocimiento
- **Dashboard de Estadísticas**: Métricas y tendencias históricas

### ⚙️ Configuración Flexible
- **Múltiples configuraciones**: Soporte para varios archivos de log simultáneos
- **Seguimiento de posición**: Ingesta incremental sin reprocesar datos
- **Retención configurable**: Limpieza automática de datos antiguos
- **Validación en tiempo real**: Pruebas de configuración con estadísticas

### 🚨 Sistema de Alertas
- **Alertas automáticas**: Generación automática para eventos críticos y de alta prioridad
- **Reconocimiento de alertas**: Sistema de gestión de alertas pendientes
- **Notificaciones**: Integración con sistema de notificaciones del SIEM

### 📈 Estadísticas y Métricas
- **Estadísticas diarias**: Agregación automática de eventos por día
- **Distribución por severidad**: Análisis de eventos por nivel de criticidad
- **Tendencias temporales**: Gráficos de evolución de eventos
- **Métricas de rendimiento**: Estadísticas de procesamiento y errores

## Instalación y Configuración

### 1. Migraciones de Base de Datos

```bash
python manage.py makemigrations ids_ingest
python manage.py migrate
```

### 2. Configuración de Archivos de Log

1. Acceder a la interfaz de configuración: `/ids-ingest/config/`
2. Crear una nueva configuración:
   - **Tipo**: Seleccionar Snort o Suricata
   - **Ruta de Log**: Ruta completa al archivo de log
   - **Activo**: Habilitar ingesta automática
   - **Retención**: Días de retención de datos

### 3. Comando de Ingesta

```bash
# Procesar todas las configuraciones activas
python manage.py ingest_ids_logs

# Procesar configuración específica
python manage.py ingest_ids_logs --config-id 1

# Forzar procesamiento completo
python manage.py ingest_ids_logs --force-full

# Modo de prueba (sin guardar)
python manage.py ingest_ids_logs --dry-run

# Configurar tamaño de lote
python manage.py ingest_ids_logs --batch-size 500
```

## Uso de la Interfaz

### Dashboard de Configuración
- **URL**: `/ids-ingest/config/`
- **Funcionalidades**:
  - Crear, editar y eliminar configuraciones
  - Probar configuraciones con estadísticas
  - Activar/desactivar ingesta
  - Ver estado de procesamiento

### Dashboard de Snort
- **URL**: `/ids-ingest/snort/`
- **Funcionalidades**:
  - Visualización de eventos con paginación
  - Filtros por severidad, IP, protocolo
  - Búsqueda en tiempo real
  - Estadísticas de eventos

### Dashboard de Suricata
- **URL**: `/ids-ingest/suricata/`
- **Funcionalidades**:
  - Análisis de eventos Suricata
  - Filtros avanzados
  - Estadísticas en tiempo real
  - Integración con análisis de IPs

### Dashboard de Alertas
- **URL**: `/ids-ingest/alerts/`
- **Funcionalidades**:
  - Gestión de alertas críticas
  - Reconocimiento de alertas
  - Filtros por severidad y estado
  - Historial de reconocimientos

### Dashboard de Estadísticas
- **URL**: `/ids-ingest/statistics/`
- **Funcionalidades**:
  - Métricas generales del sistema
  - Gráficos de tendencias
  - Distribución por severidad
  - Estadísticas históricas

## Formatos de Log Soportados

### Snort
```
12/31-23:59:59.123456 [**] [1:1000001:1] "Suspicious activity detected" [**] [Priority: 1] {TCP} 192.168.1.100:1234 -> 10.0.0.1:80
```

### Suricata
```
12/31/2024-23:59:59.123456 [**] [1:1000001:1] ET MALWARE Suspicious Activity [**] [Classification: Potentially Bad Traffic] [Priority: 1] {TCP} 192.168.1.100:1234 -> 10.0.0.1:80
```

### Suricata JSON
```json
{"timestamp":"2024-12-31T23:59:59.123456Z","flow_id":1234567890,"pcap_cnt":1,"event_type":"alert","src_ip":"192.168.1.100","src_port":1234,"dest_ip":"10.0.0.1","dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":1000001,"rev":1,"signature":"ET MALWARE Suspicious Activity","category":"Potentially Bad Traffic","severity":1}}
```

## API Endpoints

### Configuración
- `GET /ids-ingest/config/` - Listar configuraciones
- `POST /ids-ingest/config/test/<id>/` - Probar configuración
- `POST /ids-ingest/config/toggle/<id>/` - Activar/desactivar ingesta

### Dashboards
- `GET /ids-ingest/snort/` - Dashboard Snort
- `GET /ids-ingest/suricata/` - Dashboard Suricata
- `GET /ids-ingest/alerts/` - Dashboard de alertas
- `GET /ids-ingest/statistics/` - Dashboard de estadísticas

### Alertas
- `POST /ids-ingest/alerts/acknowledge/<id>/` - Reconocer alerta

## Modelos de Datos

### IDSIngestConfig
Configuración de ingesta para archivos de log específicos.

### SnortLog / SuricataLog
Eventos parseados de los sistemas IDS/IPS.

### IDSAlert
Alertas críticas generadas automáticamente.

### IDSStatistics
Estadísticas agregadas por día y tipo de IDS.

## Monitoreo y Mantenimiento

### Logs del Sistema
Los logs del servicio se registran en el sistema de logging de Django.

### Limpieza Automática
El comando de ingesta incluye limpieza automática de datos antiguos según la configuración de retención.

### Rendimiento
- Procesamiento en lotes para mejor rendimiento
- Índices de base de datos optimizados
- Seguimiento de posición para ingesta incremental

## Solución de Problemas

### Problemas Comunes

1. **Archivo de log no encontrado**
   - Verificar la ruta del archivo
   - Comprobar permisos de lectura

2. **Parsing fallido**
   - Verificar formato del log
   - Usar función de prueba en la interfaz

3. **Rendimiento lento**
   - Ajustar tamaño de lote
   - Verificar índices de base de datos

### Logs de Debug
```python
import logging
logging.getLogger('ids_ingest').setLevel(logging.DEBUG)
```

## Contribución

Para contribuir al desarrollo del servicio IDS/IPS:

1. Seguir las convenciones de código del proyecto
2. Incluir tests para nuevas funcionalidades
3. Actualizar documentación según sea necesario
4. Verificar compatibilidad con formatos de log existentes

## Licencia

Este servicio es parte del proyecto Vigilance & Neutralization threads SIEM y está sujeto a la misma licencia.
