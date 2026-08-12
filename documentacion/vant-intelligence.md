# vant-intelligence

Servicio de **inteligencia**: reputacion de IP/MAC (AbuseIPDB, MAC Vendors, VirusTotal), jobs de escaneo y **analiticas geograficas** (mapa de amenazas).

- Puerto: **8700**
- Base de datos: `vant_intelligence`
- Prefijo URL: `/api/`

## Descripcion

Enriquece los indicadores de la plataforma consultando proveedores externos (AbuseIPDB, MAC Vendors, VirusTotal), gestiona las **API keys** por proveedor y calcula las **analiticas geo** de eventos (origen/destino por pais) que alimentan el mapa de amenazas en vivo del dashboard.

## Estructura

```
vant-intelligence/
├── config/
├── intelligence_app/
│   ├── db_router.py       # routing hacia vant_intelligence
│   ├── services.py        # logica de analiticas geo
│   ├── models.py          # ApiKey, IpReport, MacLookup, VtReport, ScanJob
│   ├── views.py
│   └── urls.py
└── manage.py
```

## Modelos

| Modelo | Funcion |
|--------|---------|
| `IntelligenceApiKey` | API keys por proveedor (abuseipdb, macvendors, virustotal) |
| `IntelligenceIpReport` | Reportes de reputacion IP |
| `IntelligenceMacLookup` | Consultas MAC |
| `IntelligenceVtReport` | Reportes VirusTotal |
| `IntelligenceScanJob` | Jobs de escaneo masivo |

## Endpoints

| Ruta | Metodo | Funcion |
|------|--------|---------|
| `/api/health/` | GET | Health check |
| `/api/ip/lookup/` | GET | Consulta de reputacion de IP |
| `/api/ip/reports/` | GET | Listar reportes IP |
| `/api/ip/reports/<pk>/` | GET | Detalle de reporte IP |
| `/api/mac/lookup/` | GET | Consulta de fabricante por MAC |
| `/api/vt/lookup/` | GET | Consulta VirusTotal (IP/dominio/URL/hash) |
| `/api/keys/` | GET | Listar API keys |
| `/api/keys/<provider>/` | GET/PATCH/DELETE | Gestion de API key |
| `/api/keys/<provider>/test/` | POST | Probar API key |
| `/api/jobs/` | GET | Listar scan jobs |
| `/api/jobs/<pk>/` | GET | Detalle de job |
| `/api/jobs/create/` | POST | Crear job de escaneo |
| `/api/stats/` | GET | Estadisticas |
| `/api/analytics/dashboard/` | GET | Datos del dashboard de analiticas |
| `/api/analytics/geo/` | GET | Datos geo agregados (paises, flujos) |
| `/api/dashboard/` | GET | Dashboard interno |

### Mapa de amenazas en vivo

- El dashboard `vant-web` renderiza el mapa y hace poll a `/siem/dashboard/inteligencia/geo/live/`.
- `intelligence_geo_live` proxya a `/api/analytics/geo/live/` (tambien disponible en `vant-intelligence`) con parametros `since`, `lat`, `lon`.
- El endpoint devuelve `{connections: [...], last_event_time, ...}`.

> Nota: el endpoint `geo/live/` no aparece en `intelligence_app/urls.py`; se documenta como ruta del servicio (consumida a traves de `vant-web`). Verificar su definicion en `views.py`.

## Configuracion

| Variable | Uso |
|----------|-----|
| `INTELLIGENCE_SERVICE_URL` | URL interna |
| API keys por proveedor | Guardadas en BD (`IntelligenceApiKey`), gestionadas desde el dashboard |

## Integracion

- `vant-web` consume: `intel_ip_lookup`, `intel_mac_lookup`, `intel_vt_lookup`, `intel_api_keys`, `intel_analytics_geo`, etc.
- El mapa de amenazas usa `intelligence_geo` (pagina) + `intelligence_geo_live` (poll).
