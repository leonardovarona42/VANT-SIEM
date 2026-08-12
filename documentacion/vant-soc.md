# vant-soc

Servicio de **Security Operations Center**: gestion de incidentes, bitacora, reportes, DLP, topologia de red y monitoreo de servicios.

- Puerto: **8500**
- Base de datos: `vant_soc`
- Prefijo URL: `/api/` (y `/soc/`)

## Descripcion

Es el corazon operativo del SIEM. Centraliza el **ciclo de vida del incidente** (creacion, atencion, solucion), la **bitacora** conforme a normativas, los **reportes**, el modulo **DLP**, la **topologia de red** (servicios, IPs, conexiones), el monitoreo de servicios y las politicas de **retencion/backups** de la base de datos.

Ademas hospeda el **consumidor SOAR** (`consume_soar_events`) que crea reportes automaticos a partir de las predicciones del servicio `vant-soar`.

## Estructura

```
vant-soc/
├── config/
├── soc_app/
│   ├── management/commands/
│   │   ├── consume_soar_events.py   # consumidor del stream 'threats' (SOAR -> reportes)
│   │   ├── seed_soc.py / seed_soc_full.py / seed_zones.py
│   │   └── check_icmp.py
│   ├── models.py       # DLP + Incidente, Reporte, Servicio, ... (23 modelos)
│   ├── views.py        # view functions + ViewSets
│   ├── serializers.py
│   └── urls.py
└── manage.py
```

## Modelos (bloques)

### DLP

| Modelo | Funcion |
|--------|---------|
| `DlpPolicy` | Politicas de escaneo |
| `DlpRule` | Reglas de deteccion |
| `DlpThreat` | Amenazas detectadas |
| `DlpScanSummary` | Resumen de escaneos |

### Bitacora / Incidentes (cumplimiento Resolucion 105)

| Modelo | Funcion |
|--------|---------|
| `Categoria` / `Subcategoria` | Clasificacion de incidentes |
| `Responsable` | Responsables |
| `Area` | Areas de la organizacion |
| `Medida` | Medidas de respuesta |
| `Reporte` | Reportes (incluye los creados por SOAR) |
| `Incidente` | Incidente con ciclo de vida |
| `Involucrado` / `InvolucradoIncidente` | Involucrados y su relacion con incidentes |
| `MedidaIncidente` / `MedidaInvolucrado` | Medidas aplicadas |

### Red / Monitoreo

| Modelo | Funcion |
|--------|---------|
| `Servicio` | Servicios de red |
| `ServicioIP` | IPs de un servicio (columna `ip_address`) |
| `PuertoDispositivo` | Puertos de dispositivos |
| `ConexionTopologica` | Conexiones para la topologia |
| `MonitoreoServicio` / `ConfiguracionMonitoreo` | Monitoreo de servicios |

### Mantenimiento

| Modelo | Funcion |
|--------|---------|
| `RetentionPolicy` | Politicas de retencion de datos |
| `BackupRecord` | Registro de backups |

## Endpoints

| Ruta | Metodo | Funcion |
|------|--------|---------|
| `/api/health/` | GET | Health check |
| `/api/stats/` | GET | Estadisticas SOC |
| `/api/agent/dlp/config/` | GET | Config DLP para agentes |
| `/api/agent/dlp/threats/` | POST | Ingesta de amenazas DLP |
| `/api/agent/dlp/threats/upload/` | POST | Ingesta multipart |
| `/api/evidence/<pk>/download/` | GET | Descargar evidencia |
| `/api/incidentes/metrics/` | GET | Metricas de incidentes |
| `/api/reportes/metrics/` | GET | Metricas de reportes |
| `/api/servicios/metrics/` | GET | Metricas de servicios |
| `/api/db/health/` | GET | Salud de la BD |
| `/api/db/optimize/` | POST | Optimizar BD |
| `/api/db/backups/<pk>/restore/` | POST | Restaurar backup |

Ademas un **DRF router** (`/api/`) con ViewSets para Categoria, Subcategoria, Responsable, Area, Medida, Reporte, Incidente, Servicio, Involucrado, etc., y rutas `/soc/...` heredadas.

## Consumidor SOAR (reportes automaticos)

Comando: `manage.py consume_soar_events --group <consumer>` (unidad `vantsiem-soc-soar`).

1. Se suscribe al stream Redis **`threats`** via `vant_common.bus.EventBus`.
2. `vant-soar` publica predicciones con `event_type=soar_prediction` y `data` JSON.
3. El consumidor crea un `Reporte` en `vant_soc` con `nombre_informante='SOAR Automatico'`, `estado_solucion='nuevo'` y la descripcion/evidencia de la prediccion.
4. Si el bus no responde, usa el fallback HTTP a `SOC_URL /api/incidentes/`.

> Verificacion rapida: `select count(*) from soc_reportes where nombre_informante='SOAR Automatico';`

## Configuracion

| Variable | Uso |
|----------|-----|
| `SOC_MEDIA_ROOT` | Ruta de medios/evidencias |
| `SERVICE_SECRET` | Autorizacion interna |

## Integracion

- `vant-web` consume toda la operacion SOC via `get_incidents`, `get_reportes`, `get_servicios`, etc.
- `vant-aegis` es un modulo DLP que apunta a la misma logica.
- `vant-soar` crea reportes via el stream `threats` (automatico) o HTTP (fallback).
