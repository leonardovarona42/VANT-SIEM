# Documentacion VANT-SIEM

## Documentos principales

- `ARCHITECTURE.md`: arquitectura actual del sistema.
- `INSTALLATION.md`: instalacion y despliegue.
- `CHANGELOG.md`: cambios relevantes por version.
- `OPENSEARCH_FEATURE.md`: detalle funcional/tecnico del nuevo pipeline de logs.
- `USER_MANUAL.md`: manual de uso operativo.

## Estado de arquitectura

Desde marzo de 2026, el modulo de logs activo es OpenSearch:

- `opensearch/` -> microservicio + agentes de recoleccion.
- `opensearch_ui/` -> dashboard y Discovery en Django.
- `ids_ingest/` -> legado/deprecado en documentacion historica.

## Rutas operativas de logs

- Dashboard: `/opensearch/`
- Discovery: `/opensearch/discover/`

## Referencias de detalle

- `../opensearch/README.md`
- `../opensearch_ui/README.md`
- `OPENSEARCH_FEATURE.md`
