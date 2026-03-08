# OpenSearch UI (Django)

Modulo de visualizacion de logs para VANT-SIEM.

## Vistas

- `/opensearch/` -> dashboard general
- `/opensearch/discover/` -> Discovery avanzado

## Discovery

Caracteristicas:
- timeline de eventos por rango de tiempo
- tabla dinamica con columnas de campos base + payload
- include/exclude por celda (`+/-`)
- filtros activos en chips
- filtro de vacios (`(empty)`)
- show/hide de columnas con persistencia local

## Campos derivados de Snort

Desde `line/message` se extraen:
- `signature`
- `classification`
- `priority`
- `proto`
- `src_ip`, `src_port`
- `dst_ip`, `dst_port`
- `gid`, `sid`, `rev`

## Variables de conexion DB de logs

- `OS_DB_HOST`
- `OS_DB_PORT`
- `OS_DB_NAME`
- `OS_DB_USER`
- `OS_DB_PASSWORD`

## Notas

- Este modulo consulta la BD de logs dedicada de OpenSearch.
- No depende del antiguo `ids_ingest`.
