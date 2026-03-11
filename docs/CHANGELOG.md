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

## 2026-03-11 - Discovery + Visualizations + LDAP

### Added

- Autenticación LDAP configurable desde UI (bind, búsqueda, mapeo de atributos, auto‑creación).
- Dependencia `ldap3` para soporte LDAP.
- Descubrimiento (Discovery) con auto‑refresh sin recargar página.
- Expansión de celdas y redimensionamiento de columnas en Discovery.
- Builder de visualizaciones con fuentes dinámicas (source_type + conteo).
- Sugerencias dinámicas en custom labels según campos disponibles.

### Changed

- Filtrado include/exclude aplicado en memoria para campos derivados/payload sin SQL crudo.
- Paginación y total coherentes cuando hay filtros derivados.
- Builder de visualizaciones sincroniza selección de fuente desde el menú lateral y el selector.

### Fixed

- StartTLS aplicado antes del bind para evitar errores de “ssl wrapping”.
- Preview de visualizaciones para tipos `line/area/doughnut` mapeados a backend soportado.
