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

## Configuracion recomendada

Base de datos dedicada:
- DB: `opensearch`
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

## Arranque rapido

1. Ejecutar `python manage.py migrate` para crear tablas del sistema y aplicar el schema de OpenSearch.
2. Ejecutar `python manage.py runserver` para levantar VANT-SIEM y el servicio OpenSearch (autostart).
3. Configurar `opensearch_agents/config.yaml`.
4. Iniciar agente y verificar ingesta.

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
