# OpenSearch Service + Agent (VANT-SIEM)

Pipeline de logs desacoplado para VANT-SIEM.

## Objetivo

Sustituir la ingesta legacy por una arquitectura de microservicio + agente, con base de datos de logs dedicada.

## Componentes

- `service/`: API de ingesta y persistencia.
- `agent/`: recolector multi-fuente.
- `service/schema.sql`: esquema SQL de tablas de logs.

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

1. Aplicar schema en DB de logs.
2. Levantar servicio.
3. Configurar `agent/config.yaml`.
4. Iniciar agente y verificar ingesta.

## Plataformas de agente

- Windows (installer + scheduled task)
- Linux Debian
- Linux Ubuntu
- Linux Zentyal

Ver guias en `agent/linux/*/README.md`.
