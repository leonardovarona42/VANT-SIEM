# OpenSearch Service + Agent (VANT-SIEM)

Pipeline de logs desacoplado para VANT-SIEM.

## Objetivo

Sustituir la ingesta legacy por una arquitectura de microservicio + agente, con base de datos de logs dedicada.

## Componentes

- `opensearch_service/service/`: API de ingesta y persistencia.
- `opensearch_agents/`: recolector multi-fuente.
- `opensearch_service/service/schema.sql`: esquema SQL de tablas de logs.

## Endpoints

- `GET /health`
- `POST /api/v1/events/bulk`
- `POST /api/v1/sources/upsert`

## Configuracion recomendada

Base de datos dedicada:
- DB: `vant_opensearch`
- tablas principales: `os_events_raw`, `os_sources`

Variables de entorno servicio:
- `OS_DB_HOST`
- `OS_DB_PORT`
- `OS_DB_NAME`
- `OS_DB_USER`
- `OS_DB_PASSWORD`

## Puertos por defecto

- Servicio: `9201`
- Agent local health (opcional): `9210`

## Seguridad

Agente soporta:
- auth `none | basic | token`
- TLS on/off
- verify cert on/off
- CA custom

Control y enrolamiento desde Django:
- `GET /api/agent/bootstrap/`
- `POST /api/agent/enroll/`
- `POST /api/agent/heartbeat/`
- `POST /api/agent/inventory/`
- `POST /api/agent/commands/pull/`
- `POST /api/agent/commands/ack/`

Variables del backend de enrolamiento:
- `VANT_AGENT_ALLOWED`
- `VANT_AGENT_SHARED_SECRET`
- `VANT_AGENT_REQUIRE_ENROLLMENT_TICKET=1`

## Arranque rapido

1. Ejecutar `python manage.py migrate` para crear tablas del sistema y aplicar el schema de OpenSearch.
2. Ejecutar `python manage.py runserver` para levantar VANT-SIEM y el servicio OpenSearch (autostart).
3. Configurar `opensearch_agents/config.yaml`.
4. Iniciar agente y verificar ingesta.

## Despliegue como servicio

### Debian / Linux

Ejemplo de unidad `systemd` para el microservicio:

```ini
[Unit]
Description=VANT-SIEM OpenSearch Microservice
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
WorkingDirectory=/opt/vant-siem/opensearch_service/service
Environment=OS_SERVICE_HOST=192.168.12.43
Environment=OS_SERVICE_PORT=9201
Environment=OS_DB_HOST=127.0.0.1
Environment=OS_DB_PORT=5432
Environment=OS_DB_NAME=vant_opensearch
Environment=OS_DB_USER=postgres
Environment=OS_DB_PASSWORD=postgres
Environment=OS_AUTH_MODE=none
ExecStart=/opt/vant-siem/.venv/bin/python /opt/vant-siem/opensearch_service/service/app.py
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

Comandos:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vant-opensearch.service
sudo systemctl status vant-opensearch.service --no-pager
curl http://192.168.12.43:9201/health
```

### Windows

Instalacion del servicio en Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\opensearch_service\service\install_windows_service.ps1
```

Validacion:

```powershell
Invoke-RestMethod http://127.0.0.1:9201/health
```

## Autostart OpenSearch desde Django

Por defecto, al ejecutar `python manage.py runserver` se inicia el servicio OpenSearch en segundo plano
si no esta corriendo en `OS_SERVICE_HOST:OS_SERVICE_PORT`.

Comandos:
- `python manage.py enable_opensearch` habilita el autostart (por defecto).
- `python manage.py disable_opensearch` deshabilita el autostart.

Override por variable de entorno:
- `VANT_OS_SERVICE_AUTOSTART=0` desactiva el autostart temporalmente.

Logs del servicio:
- `logs/opensearch-service.log`
- `logs/opensearch-service.err`

## App OpenSearch (Django)

OpenSearch ahora es una app Django (`opensearch_service`) que se gestiona desde `manage.py`:
- Usa una base de datos separada (alias `opensearch`) configurada por `OS_DB_*`.
- En `python manage.py migrate`, el schema se aplica automaticamente en la DB de OpenSearch.
- En `python manage.py runserver`, el servicio se inicia automaticamente si esta habilitado.

## Plataformas de agente

- Windows (installer + scheduled task)
- Linux Debian
- Linux Ubuntu
- Linux Zentyal

Ver guias en `opensearch_agents/linux/*/README.md`.

Resumen del estado actual:
- Windows usa wizard grafico con enrolamiento y persistencia de token.
- Linux usa bundle offline con `sendheartbeat`, `opena_mover`, `opena_checker` y `opena_enroll`.

## Comandos de enrolamiento del agente

Los comandos mas importantes del agente Linux son:

```bash
sudo opena_enroll
sudo opena_enroll --enrollment-code CODIGO-DEL-TICKET
sudo opena_enroll --bootstrap-key MI-SECRETO
sudo opena_enroll --config /etc/vant-siem-agent/config.yaml
sudo opena_checker
sudo sendheartbeat --config /etc/vant-siem-agent/config.yaml
```

Para una referencia completa de despliegue y enrolamiento:

- `opensearch_agents/AGENT_MANUAL.md`
- `opensearch_agents/linux/debian/README.md`
