# vant-logs

Servicio de **ingesta, normalizacion y consulta de eventos de log** del SIEM.

- Puerto: **8400**
- Base de datos: `vant_logs`
- Prefijo URL: `/api/`

## Descripcion

Recibe los eventos de los agentes endpoint y de las fuentes de red (firewalls Eudemon, Suricata, etc.), los **normaliza** en `logs_events_raw` y los expone para consulta, estadisticas y retencion. Es la base de la correlacion (incluida la de SOAR).

## Estructura

```
vant-logs/
├── config/            # urls con todos los endpoints de log
├── logs_app/
│   ├── models.py      # LogSource, LogEventRaw, LogRetentionPolicy
│   ├── parsers.py     # parseo de eventos de cada source_type
│   ├── views.py
│   └── serializers.py
└── manage.py
```

## Modelos

| Modelo | Tabla | Funcion |
|--------|-------|---------|
| `LogSource` | `logs_sources` | Fuente de log registrada (source_id, type, vendor, host, protocol) |
| `LogEventRaw` | `logs_events_raw` | Evento normalizado |
| `LogRetentionPolicy` | - | Politica de retencion por source_type |

### Esquema `logs_events_raw`

| Campo | Tipo | Nota |
|-------|------|------|
| `id` | BigAuto | PK |
| `source` | FK -> logs_sources | Fuente |
| `source_type` | char | `windows_eventlog`, `file_log`, `suricata`, `syslog`, ... |
| `host_name` / `host_ip` | char/ip | Origen del evento |
| `event_time` | datetime | Fecha del evento (indexada) |
| `severity` | char | info/low/medium/high/critical |
| `event_category` | char | categoria normalizada |
| `message` | text | Mensaje crudo (max 5000) |
| `raw_payload` | jsonb | Payload completo (ej. `{"line": "key=value..."}` en firewalls) |
| `parsed_fields` | jsonb | Campos parseados |
| `tags` | jsonb | Etiquetas |
| `ingested_at` | datetime | Fecha de ingesta |

> **Fuente `file_log` (firewall Eudemon1000E)**: el texto viaja en `raw_payload.line` con formato `clave=valor` (ej. `attack_type=BRUTE_FORCE src_ip=45.155.205.233 dst_ip=... dst_port=21`).
> **Suricata**: usa `src_ip`/`dest_ip`/`src_port`/`dest_port`/`proto` dentro de `raw_payload`.

## Endpoints

| Ruta | Metodo | Funcion |
|------|--------|---------|
| `/api/health/` | GET | Health check |
| `/api/ingest/bulk/` | POST | Ingesta masiva de eventos (agentes y fuentes) |
| `/api/sources/` | POST | Registrar/actualizar fuente |
| `/api/sources/list/` | GET | Listar fuentes |
| `/api/sources/host-ips/` | GET | Hosts/IPs por fuente |
| `/api/sources/source-types/` | GET | Tipos de fuente |
| `/api/events/` | GET | Listar/consultar eventos (filtros) |
| `/api/events/field-values/` | GET | Valores de un campo |
| `/api/events/histogram/` | GET | Histograma temporal |
| `/api/events/<pk>/` | GET | Detalle de evento |
| `/api/statistics/` | GET | Estadisticas generales |
| `/api/statistics/suricata/` | GET | Estadisticas Suricata |
| `/api/retention/` | GET | Politicas de retencion |
| `/api/retention/cleanup/` | POST | Limpiar segun retencion |
| `/api/storage/dashboard/` | GET | Dashboard de almacenamiento |

## Configuracion

| Variable | Uso |
|----------|-----|
| `LOGS_SERVICE_URL` | URL interna (para otros servicios) |
| `SERVICE_SECRET` | Autorizacion de ingestas internas |

## Integracion

- **Ingesta**: `VANT-Agent` y fuentes de red hacen `POST /logs/api/ingest/bulk/`.
- **Consumo**: `vant-soar` (worker) consulta `logs_events_raw` para construir features y predecir; `vant-web` consulta eventos/estadisticas para el dashboard.
