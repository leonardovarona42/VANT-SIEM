# Documentacion VANT-SIEM

## Documentos principales

- `ARCHITECTURE.md`: arquitectura actual del sistema.
- `INSTALLATION.md`: instalacion y despliegue.
- `CHANGELOG.md`: cambios relevantes por version.
- `OPENSEARCH_FEATURE.md`: detalle funcional/tecnico del nuevo pipeline de logs.
- `AGENT_MICROSERVICES.md`: arquitectura funcional de `asset_audit` y `aegis_dlp`.
- `DLP_CLASSIFICATION_GUIDE.md`: lineamientos para informacion clasificada, secreta y restringida.
- `USER_MANUAL.md`: manual de uso operativo.

## Documentos operativos recomendados

Si quieres desplegar el sistema, usa este orden:

1. `INSTALLATION.md`
2. `../opensearch_service/README.md`
3. `../opensearch_agents/AGENT_MANUAL.md`
4. `../opensearch_agents/linux/debian/README.md`

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

## Comandos clave de enrolamiento

Linux:

```bash
sudo opena_enroll
sudo opena_enroll --enrollment-code CODIGO-DEL-TICKET
sudo opena_enroll --bootstrap-key MI-SECRETO
sudo opena_checker
sudo sendheartbeat --config /etc/vant-siem-agent/config.yaml
```

Windows:

```powershell
.\opensearch_agents\windows\opensearch_agent_setup.exe
```

El boton `Probar conexion` hace:

- bootstrap
- firma
- enroll
- guardado del token
