# vant-aegis

Modulo **DLP standalone** (Data Loss Prevention) del ecosistema VANT.

- Puerto: **8550** (dedicado via `GUNICORN_BIND`; el default 8500 choca con `vant-soc`)
- Base de datos: `vant_soc` (comparte modelos DLP)
- Prefijo URL: `/api/`

## Descripcion

Aplicacion Django independiente que implementa el modulo **DLP**: politicas de escaneo, reglas de deteccion, ingesta de amenazas desde los agentes y estadisticas. Funcionalmente es equivalente a la parte DLP de `vant-soc` (mismos modelos de datos).

## Estructura

```
vant-aegis/
├── config/
├── aegis_app/
│   ├── models.py      # DlpPolicy, DlpRule, DlpThreat, DlpScanSummary
│   ├── views.py       # health, stats, agent config/ingest, evidence
│   ├── serializers.py
│   └── urls.py
└── manage.py
```

## Modelos

| Modelo | Funcion |
|--------|---------|
| `DlpPolicy` | Politicas de escaneo (paths, extensiones, tamano max) |
| `DlpRule` | Reglas de deteccion (keyword, regex, metadata) |
| `DlpThreat` | Amenazas detectadas |
| `DlpScanSummary` | Resumen de escaneos |

## Endpoints

| Ruta | Metodo | Funcion |
|------|--------|---------|
| `/api/health/` | GET | Health check |
| `/api/stats/` | GET | Estadisticas DLP |
| `/api/agent/dlp/config/` | GET | Politicas/reglas activas para agentes |
| `/api/agent/dlp/threats/` | POST | Ingesta de amenazas |
| `/api/agent/dlp/threats/upload/` | POST | Ingesta multipart (evidencias) |
| `/api/evidence/<pk>/download/` | GET | Descargar evidencia |

## Issue conocido: conflicto de puerto (resuelto)

**Resolucion aplicada** (2026-08-12): la unidad `vantsiem-aegis` estaba en **crash-loop** porque `gunicorn.conf.py` usaba por defecto `127.0.0.1:8500`, el mismo puerto que `vant-soc` (que gana el bind), y ademas agotaba el pool de PostgreSQL (`FATAL: remaining connection slots are reserved for roles with the SUPERUSER attribute`).

**Fix**: en `/opt/vant-siem/.env` se definio `GUNICORN_BIND=127.0.0.1:8550` (y `AEGIS_SERVICE_URL` alineado a 8550). La unidad quedo `active`, escuchando en 8550 y con `/api/health/` respondiendo `{"status":"healthy","service":"aegis-dlp","database":"connected",...}`. El pool de PostgreSQL tenia margen (42/100 conexiones).

> Regla para el futuro: **nunca** dejar que un servicio comparta puerto con otro; si se agrega un modulo nuevo, asignarle `GUNICORN_BIND` propio en `.env`.

## Integracion

- `vant-web` consume las APIs DLP para el dashboard de politicas/incidentes.
- Los agentes endpoint envian amenazas a `/api/agent/dlp/threats/`.
