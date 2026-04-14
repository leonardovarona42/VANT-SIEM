# Documentacion VANT-SIEM

## Documentos principales

- `ARCHITECTURE.md`: arquitectura actual del sistema.
- `INSTALLATION.md`: instalacion y despliegue.
- `CHANGELOG.md`: cambios relevantes por version.
- `OPENSEARCH_FEATURE.md`: detalle funcional/tecnico del nuevo pipeline de logs.
- `AGENT_MICROSERVICES.md`: arquitectura funcional de `asset_audit` y `aegis_dlp`.
- `DLP_CLASSIFICATION_GUIDE.md`: lineamientos para informacion clasificada, secreta y restringida.
- `USER_MANUAL.md`: manual de uso operativo.

## Estado de arquitectura

Desde marzo de 2026, el modulo de logs activo es OpenSearch:

- `opensearch_service/` -> microservicio y bootstrap del servicio de ingesta.
- `opensearch_agents/` -> agentes, installers y tooling operativo.
- `opensearch_ui/` -> dashboard y Discovery en Django.
- `inventory/` -> gestion de dispositivos, inventario y comandos del agente.
- `inventory/` -> tambien modela timeline de activos, incidentes DLP y politicas Aegis.
- `ids_ingest/` -> legado/deprecado en documentacion historica.

## Rutas operativas de logs

- Dashboard: `/opensearch/`
- Discovery: `/opensearch/discover/`
- Devices Management: `/siem/dashboard/devices/management/`
- Inventory Service: `/siem/dashboard/devices/inventory/`
- Aegis DLP: `/siem/dashboard/devices/dlp/`

## Referencias de detalle

- `../opensearch_service/README.md`
- `../opensearch_ui/README.md`
- `OPENSEARCH_FEATURE.md`
- `AGENT_MICROSERVICES.md`
- `DLP_CLASSIFICATION_GUIDE.md`
- `../opensearch_agents/AGENT_MANUAL.md` (Agente v1.01)
