# VANT-SIEM

Plataforma SIEM en Django con gestion de incidentes, analitica de seguridad y pipeline de logs basado en OpenSearch (microservicio + agente).

## Estado actual (2026-03)

- `ids_ingest` fue retirado del flujo principal.
- El pipeline activo de logs es:
  - `opensearch/` (microservicio de ingesta + agentes)
  - `opensearch_ui/` (dashboard y Discovery en Django)
- La base de datos de logs es dedicada (`opensearch`) y separada de la BD principal del SIEM.

## Componentes

- `CORE/`: configuracion Django.
- `EVENT_M/`: gestion de incidentes y reportes.
- `VANT_SIEM/`: nucleo SIEM (auth, notificaciones, panel principal).
- `opensearch/`: servicio HTTP de ingesta, schema SQL, agentes multiplataforma.
- `opensearch_ui/`: dashboards de logs y Discovery estilo Kibana.
- `docs/`: documentacion funcional y tecnica.

## OpenSearch (feature principal)

- Ingesta por lotes: `POST /api/v1/events/bulk`
- Health: `GET /health`
- Puerto por defecto del servicio: `9201`
- Agente configurable para Snort, Suricata, Windows Event Logs, Samba AD y PostgreSQL.
- Soporte TLS/autenticacion (`none`, `basic`, `token`).

## OpenSearch UI

- Dashboard: `/opensearch/`
- Discovery: `/opensearch/discover/`
- Filtros por atributo include/exclude
- Control dinamico de columnas (show/hide)
- Timeline + tabla de eventos

## Inicio rapido

1. Crear/activar entorno virtual e instalar dependencias.
2. Configurar BD principal Django en `CORE/settings.py`.
3. Configurar BD de logs para OpenSearch (ej. `opensearch`).
4. Aplicar migraciones Django:

```bash
python manage.py migrate
```

5. Levantar Django:

```bash
python manage.py runserver 0.0.0.0:8000
```

6. Levantar servicio OpenSearch (Windows):

```powershell
powershell -ExecutionPolicy Bypass -File .\opensearch\service\install_windows_service.ps1
```

7. Instalar agente OpenSearch (Windows):

```powershell
powershell -ExecutionPolicy Bypass -File .\dist\opensearch-agent-installer\package\Install-OpenSearchAgent.ps1 -RunNow
```

## Documentacion

- `docs/README.md`
- `docs/ARCHITECTURE.md`
- `docs/INSTALLATION.md`
- `docs/CHANGELOG.md`
- `docs/OPENSEARCH_FEATURE.md`
- `opensearch/README.md`
- `opensearch_ui/README.md`
