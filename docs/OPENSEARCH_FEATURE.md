# OpenSearch Feature - Documentacion Tecnica

## Objetivo

Reemplazar la ingesta legacy (`ids_ingest`) por una arquitectura escalable similar a SIEMs modernos:

- microservicio de ingesta desacoplado
- agente de recoleccion multi-sistema
- base de datos de logs dedicada
- UI de exploracion tipo Discover

## Componentes

## 1) Microservicio (`opensearch/service`)

Funciones:
- endpoint de ingesta por lotes
- validacion basica de payload
- persistencia en PostgreSQL de logs

Endpoint principal:
- `POST /api/v1/events/bulk`

Health:
- `GET /health`

## 2) Agente (`opensearch/agent`)

Funciones:
- lectura de fuentes de logs
- normalizacion de evento
- envio batch al microservicio
- retries y logs locales

Fuentes soportadas:
- Snort
- Suricata
- Windows Event Logs / AD
- Samba AD (Zentyal)
- PostgreSQL

## 3) UI (`opensearch_ui`)

- Dashboard operativo de eventos.
- Discovery avanzado:
  - filtros include/exclude por celda (`+/-`)
  - filtros de vacio (`(empty)`)
  - columnas dinamicas
  - control show/hide de columnas
  - timeline sobre tabla

## Base de datos de logs

Tabla principal:
- `os_events_raw`

Campos base esperados:
- `id`
- `source_type`
- `source_name`
- `host_name`
- `event_time`
- `severity`
- `event_category`
- `message`
- `raw_payload`
- `tags`
- `ingested_at`

## Seguridad y transporte

Config del agente:
- `auth.mode`: `none | basic | token`
- `tls.enabled`: `true | false`
- `tls.verify`: `true | false`
- `tls.ca_cert`: ruta opcional

## Puertos por defecto

- Servicio OpenSearch: `9201`
- Django: `8000`
- PostgreSQL: configurable (comunmente `5432`)

## Operacion recomendada

1. Mantener SIEM Django y logs OpenSearch en BDs separadas.
2. Aplicar indices sobre `event_time`, `source_type`, `event_category`.
3. Usar filtros por rango de tiempo corto por defecto (5m) y ampliar segun necesidad.
4. Validar health del servicio y estado del agente en cada host.

## Estado de migracion

- OpenSearch: activo y principal.
- ids_ingest: legado/deprecado.
