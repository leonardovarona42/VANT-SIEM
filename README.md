# VANT-SIEM

VANT-SIEM es una plataforma de gestión de seguridad orientada a detección, analítica y respuesta operativa. Combina SIEM tradicional (eventos, alertas, investigación) con un pipeline moderno de logs basado en OpenSearch para lograr visibilidad en tiempo casi real, trazabilidad y capacidad de escalado.

## Objetivo del proyecto

Entregar una plataforma unificada para:

- centralizar eventos de seguridad de múltiples fuentes,
- correlacionar y priorizar riesgos,
- apoyar decisiones de respuesta con analítica y predicción,
- fortalecer el aseguramiento operativo y la continuidad del servicio.

## Cualidades clave

- Arquitectura desacoplada: separa la operación SIEM de la ingesta de alto volumen.
- Escalabilidad operativa: microservicio de logs + agente multi-fuente.
- Observabilidad completa: dashboards, Discovery, filtros por atributo y trazabilidad.
- Integridad de datos: normalización, deduplicación y persistencia en base dedicada.
- Seguridad de transporte: soporte de TLS y autenticación configurable.

## Servicios y módulos

- `CORE/`: configuración y orquestación Django.
- `VANT_SIEM/`: núcleo SIEM (autenticación, notificaciones, panel principal).
- `EVENT_M/`: gestión de incidentes, reportes y seguimiento.
- `IRIS/`: capacidades de analítica asistida y automatización.
- `opensearch/`: microservicio de ingesta y agentes.
- `opensearch_ui/`: dashboard de logs y Discovery avanzado.

## Pipeline OpenSearch (estado actual)

`ids_ingest` fue retirado del flujo principal. El pipeline activo es:

- `opensearch/service`: recibe y persiste eventos en lotes.
- `opensearch/agent`: recolecta logs de Snort, Suricata, Windows Event Logs, Samba AD y PostgreSQL.
- `opensearch_ui`: visualización operativa y exploración avanzada.

Base de datos de logs: dedicada (`opensearch`) y separada de la BD principal del SIEM.

## Analítica, predicción y aseguramiento

La plataforma integra capacidades para evolucionar de monitoreo reactivo a operación preventiva:

- Analítica de comportamiento y tendencias temporales.
- Priorización de eventos por severidad y contexto.
- Correlación entre fuentes heterogéneas.
- Base para modelos predictivos de riesgo y saturación operativa.
- Evidencia auditable para cumplimiento, respuesta y mejora continua.

## OpenSearch UI - Dashboards y Visualizaciones

### Dashboards Disponibles

- **Dashboard Principal**: `/opensearch/` - Vista general de eventos
- **Snort Dashboard V2**: `/opensearch/snort/v2/` - Dashboard especializado para Snort IDS con:
  - Stats de alertas críticas, altas, medias y totales
  - Gráficos de timeline de alertas
  - Top mensajes de alerta
  - Top IPs fuente y destino
  - Tabla de alertas recientes
  - Selector de rango de tiempo (5m, 15m, 1h, 6h, 24h, 7d, All)
  - Estilo Kibana/Wazuh oscuro

- **Discovery**: `/opensearch/discover/` - Exploración avanzada de logs

### Constructor de Visualizaciones

- **Acceso**: `/opensearch/visualizations/create/`
- **Características**:
  - Tipos de gráfico: Line, Bar, Area, Pie/Donut, Heatmap, Table, Metric, Gauge, Scatter, Radar
  - Fuentes de datos: All Indices, Snort IDS, Suricata
  - Configuración de métricas: Count, Average, Sum, Min, Max, Cardinality, Percentiles
  - Buckets configurables: Date Histogram, Terms, Filters
  - Opciones avanzadas de chart:
    - Título del chart
    - Posición de leyenda
    - Líneas de grid
    - Esquema de colores
    - Stacking (para Bar/Area)
    - Modo porcentaje
    - Opacidad de relleno
    - Radio de puntos
    - Tensión de línea (curvas)
    - Animaciones
    - Etiquetas de datos
  - Preview en tiempo real
  - Guardar visualizaciones

### Funcionalidades del Discovery

- Filtros include/exclude por atributo.
- Manejo de campos vacíos `(empty)`.
- Show/Hide dinámico de columnas.
- Timeline + tabla de eventos de alta densidad.

## Inicio rápido

1. Crear y activar entorno virtual.
2. Instalar dependencias.
3. Configurar BD principal Django en `CORE/settings.py`.
4. Configurar BD dedicada de logs (`opensearch`).
5. Ejecutar migraciones y levantar Django.
6. Instalar/iniciar servicio OpenSearch y agente.

```bash
python manage.py migrate
python manage.py runserver 0.0.0.0:8000
```

Servicio OpenSearch (Windows):

```powershell
powershell -ExecutionPolicy Bypass -File .\opensearch\service\install_windows_service.ps1
```

Agente OpenSearch (Windows):

```powershell
powershell -ExecutionPolicy Bypass -File .\dist\opensearch-agent-installer\package\Install-OpenSearchAgent.ps1 -RunNow
```

## Documentación

- `docs/README.md`
- `docs/ARCHITECTURE.md`
- `docs/INSTALLATION.md`
- `docs/CHANGELOG.md`
- `docs/OPENSEARCH_FEATURE.md`
- `opensearch/README.md`
- `opensearch_ui/README.md`

## Tecnologías utilizadas

- **Backend**: Django 5.x, Python 3.12
- **Base de datos**: PostgreSQL, SQLite (dev)
- **Logs**: OpenSearch, PostgreSQL (opensearch)
- **Frontend**: Bootstrap 5, Chart.js, Font Awesome
- **IA/ML**: scikit-learn, NumPy, Pandas
- **Agentes**: Python (multi-plataforma)
