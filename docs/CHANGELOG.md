# Changelog

## 2026-03-07 - OpenSearch logs pipeline (major)

### Added

- Nuevo microservicio `opensearch/service` para ingesta de eventos.
- Nuevo agente `opensearch/agent` multi-fuente:
  - Snort
  - Suricata
  - Windows Event Logs / Active Directory
  - Samba AD (Zentyal)
  - PostgreSQL logs
- Nueva UI `opensearch_ui` con:
  - Dashboard de logs
  - Discovery estilo Kibana
  - filtros include/exclude por atributo
  - timeline + tabla de alta densidad
  - show/hide de columnas persistente

### Changed

- Arquitectura de logs migrada desde `ids_ingest` a OpenSearch.
- Separacion de base de datos de logs para aislamiento de carga.
- Navegacion principal actualizada para usar OpenSearch Discovery.

### Fixed

- Render/parse de campos Snort derivados desde `line` (signature, classification, priority, proto, src/dst, gid/sid/rev).
- Filtros por campos vacios (`(empty)`) en Discovery.
- Estabilidad de grafica temporal en carga de pagina.

### Deprecated/Removed

- `ids_ingest` marcado como legado y removido del flujo principal.
