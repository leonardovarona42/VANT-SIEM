# Arquitectura, Despliegue y Operacion

Documento general de la plataforma **VANT-SERVICES**: topologia, despliegue en servidor, configuracion y operacion.

---

## 1. Topologia de despliegue

Todos los servicios corren en un **unico servidor** (Linux, `192.168.12.43`, hostname `sv-testing`), escuchando solo en `127.0.0.1`, y son expuestos por un **nginx** en el puerto 443.

```
Internet / LAN
      │
      ▼
  nginx :443 (SSL)
      ├── /siem/            -> vant-web    (:8200)  Dashboard
      ├── /auth/            -> vant-auth   (:8100)
      ├── /inventory/api/   -> vant-inventory (:8300)  API agentes
      ├── /logs/api/        -> vant-logs   (:8400)  Ingesta + consulta
      ├── /soc/api/         -> vant-soc    (:8500)  DLP + bitacora
      ├── /api/alerts/      -> vant-bus    (:8600)
      ├── /intel/api/       -> vant-intelligence (:8700)
      └── /                 -> vant-web    (:8200)
```

### Comunicacion entre servicios

- **HTTP interno**: cada servicio expone `/api/...` en `127.0.0.1:<puerto>`. `vant-web` es el unico punto de entrada externo y proxya mediante `vant_common.http_client`.
- **Autenticacion entre servicios**: header de confianza `SERVICE_SECRET` via `vant_common.auth`.
- **Bus de eventos**: `vant-bus` sobre **Redis Streams** (PUBLISH/SUBSCRIBE con consumer groups) para eventos de sistema, notificaciones y streams como `threats`.
- **Redis**: `redis://127.0.0.1:6379/0` es el broker central (streams + cache).
- **El SOAR** (`:8800`) y sus workers no se exponen por nginx; el dashboard lo consume via proxy de `vant-web`.
- **Entrada de agentes/firewalls**: ingesta directa a `/logs/api/ingest/bulk/` (via nginx); DLP de agentes a `/soc/api/agent/dlp/threats/`.

## 2. Puertos y unidades systemd

| Servicio | Puerto | Unidad | Log |
|----------|--------|--------|-----|
| auth | 8100 | `vantsiem-auth` | `/var/log/vant/auth.log` |
| web | 8200 | `vantsiem-web` | `/var/log/vant/web.log` |
| inventory | 8300 | `vantsiem-inventory` | `/var/log/vant/inventory.log` |
| logs | 8400 | `vantsiem-logs` | `/var/log/vant/logs.log` |
| soc | 8500 | `vantsiem-soc` | `/var/log/vant/soc.log` |
| bus | 8600 | `vantsiem-bus` | `/var/log/vant/bus.log` |
| intelligence | 8700 | `vantsiem-intelligence` | `/var/log/vant/intelligence.log` |
| soar | 8800 | `vantsiem-soar` | `/var/log/vant/soar.log` |
| soar-worker | - | `vantsiem-soar-worker` | `/var/log/vant/soar-worker.log` |
| soc-soar (consumidor) | - | `vantsiem-soc-soar` | `/var/log/vant/soc-soar.log` |
| aegis | 8550 | `vantsiem-aegis` | `/var/log/vant/aegis.log` |
| icmp-monitor | - | `vantsiem-icmp-monitor` | - |
| health-check | - | `vantsiem-health-check` (inactivo) | - |

Las unidades estan en `scripts/vantsiem-*.service` y se instalan en `/etc/systemd/system/`. Patron comun:

```ini
[Unit]
Description=VANT-SIEM X (:PORT)
After=network.target postgresql.service redis-server.service vantsiem-auth.service
Requires=postgresql.service redis-server.service

[Service]
Type=simple
User=leonardo
WorkingDirectory=/opt/vant-siem/services/vant-X
Environment=PATH=/opt/vant-siem/venv/bin:/usr/bin:/bin
EnvironmentFile=/opt/vant-siem/.env
ExecStart=/opt/vant-siem/venv/bin/gunicorn --config /opt/vant-siem/services/vant-X/gunicorn.conf.py
Restart=always
RestartSec=5
StandardOutput=append:/var/log/vant/X.log
StandardError=append:/var/log/vant/X.log
```

## 3. Layout del servidor

```
/opt/vant-siem/
├── .env                     # configuracion central (todos los servicios)
├── venv/                    # entorno virtual Python 3.13 compartido
├── shared/vant_common/      # libreria compartida (fuente)
├── services/
│   ├── vant-auth/ vant-web/ vant-inventory/ vant-logs/ vant-soc/
│   ├── vant-bus/ vant-intelligence/ vant-soar/ vant-aegis/
│   └── (cada uno con manage.py, config/, gunicorn.conf.py, requirements.txt)
└── (venv/lib/python3.13/site-packages/vant_common/)  # copia instalada
```

> **Importante**: `vant_common` puede quedar instalado como copia en `site-packages` (no editable). Si se edita `shared/vant_common/*`, copiar tambien a `site-packages/vant_common/` y reiniciar los servicios.

## 4. Configuracion (`/opt/vant-siem/.env`)

| Grupo | Variables |
|-------|-----------|
| PostgreSQL | `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_USER`, `POSTGRES_PASSWORD` |
| Redis | `REDIS_URL=redis://127.0.0.1:6379/0`, `REDIS_STREAM_MAX_LEN` |
| JWT | `JWT_SECRET`, `JWT_ACCESS_TTL`, `JWT_REFRESH_TTL` |
| Confianza | `SERVICE_SECRET` |
| URLs de servicios | `AUTH_SERVICE_URL`, `WEB_SERVICE_URL`, `INVENTORY_SERVICE_URL`, `LOGS_SERVICE_URL`, `AEGIS_SERVICE_URL`, `BUS_SERVICE_URL`, `INTELLIGENCE_SERVICE_URL`, `SOAR_SERVICE_URL` |
| Alertas | `ALERT_EMAIL_*`, `ALERT_TELEGRAM_*`, `ALERT_WEBHOOK_*` |
| MinIO (opcional) | `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, `MINIO_BUCKET` |
| Agentes | `AGENT_DLP_SCAN_INTERVAL`, `AGENT_INVENTORY_INTERVAL`, `AGENT_HEARTBEAT_INTERVAL` |
| SOC | `SOC_MEDIA_ROOT` |

## 5. Nginx

Config en `scripts/nginx-vantsiem.conf` -> `/etc/nginx/sites-enabled/vantsiem`.

- HTTP 80 -> 301 a HTTPS.
- HTTPS 443 con certificado `/etc/nginx/ssl/vsiem.pem` / `.key`.
- **Zonas de rate limiting**: `auth` (10 r/s), `api_agent` (100 r/s), `api_user` (20 r/s), `ingest` (50 r/s).
- `client_max_body_size 50M`, timeouts de proxy 120s.
- Bloques de proxy: `/auth/`, `/inventory/api/`, `/logs/api/ingest/`, `/logs/api/`, `/soc/api/agent/`, `/soc/api/`, `/soc/`, `/api/alerts/`, `/api/events/recent/`, `/static/`, `/media/`, `/siem/`, `/eventos/`, `/inventory/`, `/admin/`, `/intel/api/`, `/` (fallback a web).

## 6. Bases de datos

Creadas con owner `vantsiem`:

```sql
CREATE DATABASE vant_auth OWNER vantsiem;
CREATE DATABASE vant_web OWNER vantsiem;
CREATE DATABASE vant_inventory OWNER vantsiem;
CREATE DATABASE vant_logs OWNER vantsiem;
CREATE DATABASE vant_soc OWNER vantsiem;
CREATE DATABASE vant_bus OWNER vantsiem;
CREATE DATABASE vant_intelligence OWNER vantsiem;
CREATE DATABASE vant_soar OWNER vantsiem;
```

| Base | Servicio | Contenido principal |
|------|----------|---------------------|
| `vant_auth` | auth | AuthUser, AuthAgentToken, AuthAuditLog |
| `vant_web` | web | Sesiones, notificaciones web |
| `vant_inventory` | inventory | Agent, HardwareInventory, SoftwareInventory, AgentCommand |
| `vant_logs` | logs | LogSource, LogEventRaw (`logs_events_raw`), LogRetentionPolicy |
| `vant_soc` | soc | DLP + Incidente, Reporte, Servicio, Area, Medida, Involucrado, ... |
| `vant_bus` | bus | SystemEvent, NotificationGroup, ServiceConfig, AlertChannel |
| `vant_intelligence` | intelligence | IntelligenceApiKey, IpReport, MacLookup, VtReport, ScanJob |
| `vant_soar` | soar | SoarConfig, SoarPrediction, NetworkFeature, SoarModel, Playbook |

Consola: `PGPASSWORD=... psql -h 127.0.0.1 -U vantsiem <db>`

### Migraciones

```bash
# Por servicio
cd /opt/vant-siem/services/vant-X
/opt/vant-siem/venv/bin/python manage.py migrate --noinput

# Todos (script)
/opt/vant-siem/services/scripts/migrate_all.sh
```

> `migrate_all.sh` ademas crea el superusuario `admin/admin` en `vant_auth`.

## 7. Despliegue desde la estacion de trabajo

```bash
# Script completo (paramiko): sube servicios, units, nginx, .env y reinicia
python scripts/deploy.py
python scripts/deploy.py --server IP --skip-env --skip-nginx

# Manual con el helper paramiko (rutas unix):
#   upload <local> <remoto>
#   cmd "echo pass | sudo -S systemctl restart vantsiem-X"
```

Tras actualizar codigo de un servicio: reiniciar la unidad correspondiente (`systemctl restart vantsiem-X`).

## 8. Operacion

### Estado

```bash
systemctl is-active vantsiem-*      # todos los servicios
systemctl status vantsiem-web --no-pager
journalctl -u vantsiem-soar-worker --since today
```

### Logs

| Servicio | Log |
|----------|-----|
| web | `/var/log/vant/web.log` |
| auth | `/var/log/vant/auth.log` |
| inventory | `/var/log/vant/inventory.log` |
| logs | `/var/log/vant/logs.log` |
| soc | `/var/log/vant/soc.log` |
| bus | `/var/log/vant/bus.log` |
| intelligence | `/var/log/vant/intelligence.log` |
| soar | `/var/log/vant/soar.log` |
| soar-worker | `/var/log/vant/soar-worker.log` |
| soc-soar (consumidor) | `/var/log/vant/soc-soar.log` |
| aegis | `/var/log/vant/aegis.log` |

### Logs utiles

- `tail -f /var/log/vant/web.log` - proxy y requests lentos (`slow_request ... elapsed=Xs`).
- `/var/log/vant/soar-worker.log` - ciclos del worker SOAR.
- `/var/log/vant/soc-soar.log` - consumidor de predicciones.

### Comandos utiles

```bash
systemctl is-active vantsiem-*                          # estado de todos
systemctl restart vantsiem-soar vantsiem-soar-worker    # reiniciar SOAR
journalctl -u vantsiem-web --since today                # log de unidad
PGPASSWORD=... psql -h 127.0.0.1 -U vantsiem vant_soar  # consola BD
```

### Health checks

- `curl http://127.0.0.1:8100/auth/api/health/`
- `curl http://127.0.0.1:8800/api/health/` (SOAR)

## 9. Issues conocidos

1. **`vant-aegis` (resuelto 2026-08-12)**: estaba en crash-loop por conflicto de puerto 8500 con `vant-soc` y agotamiento del pool de PostgreSQL. Se resolvio con `GUNICORN_BIND=127.0.0.1:8550` en `.env`; hoy escucha en 8550 y responde healthy. Detalle en [vant-aegis.md](vant-aegis.md).
2. **Timeouts de `xreadgroup`**: silenciosos por diseno en `vant_common.bus.EventBus` (streams sin mensajes no son errores).
3. **Copia de `vant_common`**: recordar sincronizar cambios a `site-packages` y reiniciar.

## 10. Verificacion end-to-end (SOAR)

1. `systemctl is-active vantsiem-soar vantsiem-soar-worker vantsiem-soc-soar` -> active.
2. `curl -s http://127.0.0.1:8800/api/stats/ | head -c 300` -> predicciones y modo `automatic`.
3. `select count(*) from soc_reportes where nombre_informante='SOAR Automatico';` -> reportes creandose.
4. Dashboard: `https://<host>/siem/dashboard/inteligencia/soar/`.
