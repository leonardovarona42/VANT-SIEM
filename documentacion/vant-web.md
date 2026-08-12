# vant-web

Servicio de **presentacion**: el dashboard unico de VANT-SERVICES y **proxy** hacia todos los demas servicios.

- Puerto: **8200**
- Base de datos: `vant_web` (sesiones)
- URL publica: `https://<host>/siem/dashboard/...` (via nginx)

## Descripcion

Es la unica aplicacion expuesta al usuario final. Renderiza el dashboard y delega todas las operaciones a los microservicios via HTTP interno (`http_client.py`). No accede directamente a las bases de datos de otros servicios; consume sus APIs.

## Estructura

```
vant-web/
├── config/            # settings (SOAR_SERVICE_URL, *_SERVICE_URL), urls
├── web_app/
│   ├── views.py       # ~130 vistas (dashboard, SOC, config, inteligencia, SOAR)
│   ├── http_client.py # cliente HTTP hacia todos los servicios
│   ├── urls.py        # todas las rutas /siem/dashboard/...
│   ├── templates/     # web_app/*.html (base.html, dashboards, ...)
│   └── static/
└── manage.py
```

## Rutas principales

| Ruta | Funcion |
|------|---------|
| `/siem/dashboard/` | Dashboard principal |
| `/siem/dashboard/login/` | Login |
| `/siem/dashboard/logs/...` | Dashboard de logs, almacenamiento, suricata |
| `/siem/dashboard/soc/...` | Incidentes, reportes, bitacora, DLP |
| `/siem/dashboard/configuracion/...` | Configuracion (API keys, retencion, backups) |
| `/siem/dashboard/inteligencia/` | Analiticas de inteligencia |
| `/siem/dashboard/inteligencia/geo/` | Mapa de amenazas |
| `/siem/dashboard/inteligencia/geo/live/` | Poll en vivo del mapa |
| `/siem/dashboard/inteligencia/geo/report/` | Reporte geo |
| `/siem/dashboard/inteligencia/soar/` | Dashboard SOAR |
| `/siem/dashboard/inteligencia/soar/api/<path>` | Proxy a la API de `vant-soar` |
| `/siem/dashboard/estado-recoleccion/` | Estado de recoleccion |

### Vistas SOAR (proxy)

- `intelligence_soar` - pagina del dashboard SOAR.
- `intelligence_soar_api(request, path)` - **proxy generico** a `SOAR_SERVICE_URL/api/<path>` con `@csrf_exempt` (los metodos POST/PATCH del dashboard no envian token CSRF).

## Configuracion (settings)

| Variable | Uso |
|----------|-----|
| `AUTH_SERVICE_URL` | `http://127.0.0.1:8100` |
| `WEB_SERVICE_URL` | `http://127.0.0.1:8200` |
| `INVENTORY_SERVICE_URL` | `http://127.0.0.1:8300` |
| `LOGS_SERVICE_URL` | `http://127.0.0.1:8400` |
| `AEGIS_SERVICE_URL` | `http://127.0.0.1:8500` |
| `BUS_SERVICE_URL` | `http://127.0.0.1:8600` |
| `INTELLIGENCE_SERVICE_URL` | `http://127.0.0.1:8700` |
| `SOAR_SERVICE_URL` | `http://127.0.0.1:8800` |
| `SERVICE_SECRET` | Header de confianza hacia los servicios |

## Autenticacion

- `_require_auth(request)`: autorizado si `request.session["jwt_token"]` o `request.user.is_authenticated`.
- Tras login, `vant-web` guarda el JWT en la sesion y lo reenvia como header a los servicios.

## Integracion

El cliente `http_client.py` expone una funcion por operacion (ej. `get_incidents()`, `intel_ip_lookup()`, `bus_create_group()`, `auth_list_users()`). Todas usan `_service_call()` que agrega el header de auth y `SERVICE_SECRET`.
