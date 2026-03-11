# Arquitectura VANT-SIEM (2026-03)

## Vista general

El sistema se divide en dos planos:

1. Plano SIEM (Django)
- `CORE`, `VANT_SIEM`, `EVENT_M`, `IRIS`
- Gestion de usuarios, incidentes, analitica y panel principal.

2. Plano de logs (OpenSearch)
- `opensearch/service`: API de ingesta y persistencia en DB dedicada.
- `opensearch/agent`: recoleccion multi-fuente y envio por lotes.
- `opensearch_ui`: visualizacion (dashboard + Discovery) integrada en Django.

## Flujo de datos

1. Agente recolecta eventos (Snort, Suricata, Windows, Samba AD, PostgreSQL).
2. Agente normaliza a un contrato comun.
3. Envia lotes al servicio OpenSearch (`/api/v1/events/bulk`).
4. Servicio persiste en `os_events_raw` (BD de logs dedicada).
5. `opensearch_ui` consulta y renderiza graficos/tablas con filtros.

## Almacenamiento

- BD principal Django: datos de aplicacion SIEM.
- BD OpenSearch: datos de eventos de logs (`os_events_raw`, `os_sources`).

Separar ambas BDs evita que consultas de alto volumen de logs impacten la operacion del SIEM.

## Puertos por defecto

- OpenSearch Service HTTP: `9201`
- PostgreSQL logs: `5432` (o puerto configurado)
- Django: `8000`

## Seguridad

Agente y servicio soportan:
- TLS habilitable/deshabilitable
- Verificacion de certificado
- Auth `none`, `basic`, `token`

## UI de Logs

- `/opensearch/`: resumen operativo
- `/opensearch/discover/`: exploracion avanzada
  - filtros include/exclude por campo
  - columnas dinamicas show/hide
  - timeline y tabla horizontal para alta cardinalidad
