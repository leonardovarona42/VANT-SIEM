# VANT-SIEM

VANT-SIEM es una plataforma de gestion de seguridad orientada a deteccion, analitica y respuesta operativa. Combina SIEM tradicional (eventos, alertas, investigacion) con un pipeline moderno de logs basado en OpenSearch para lograr visibilidad en tiempo casi real, trazabilidad y capacidad de escalado.

## Objetivo del proyecto

Entregar una plataforma unificada para:

- centralizar eventos de seguridad de multiples fuentes,
- correlacionar y priorizar riesgos,
- apoyar decisiones de respuesta con analitica y prediccion,
- fortalecer el aseguramiento operativo y la continuidad del servicio.

## Cualidades clave

- Arquitectura desacoplada: separa la operacion SIEM de la ingesta de alto volumen.
- Escalabilidad operativa: microservicio de logs + agente multi-fuente.
- Observabilidad completa: dashboards, Discovery, filtros por atributo y trazabilidad.
- Integridad de datos: normalizacion, deduplicacion y persistencia en base dedicada.
- Seguridad de transporte: soporte de TLS y autenticacion configurable.

## Servicios y modulos

- `CORE/`: configuracion y orquestacion Django.
- `VANT_SIEM/`: nucleo SIEM (autenticacion, notificaciones, panel principal).
- `EVENT_M/`: gestion de incidentes, reportes y seguimiento.
- `IRIS/`: capacidades de analitica asistida y automatizacion.
- `opensearch/`: microservicio de ingesta y agentes.
- `opensearch_ui/`: dashboard de logs y Discovery avanzado.

## Pipeline OpenSearch (estado actual)

`ids_ingest` fue retirado del flujo principal. El pipeline activo es:

- `opensearch/service`: recibe y persiste eventos en lotes.
- `opensearch/agent`: recolecta logs de Snort, Suricata, Windows Event Logs, Samba AD y PostgreSQL.
- `opensearch_ui`: visualizacion operativa y exploracion avanzada.

Base de datos de logs: dedicada (`opensearch`) y separada de la BD principal del SIEM.

## Analitica, prediccion y aseguramiento

La plataforma integra capacidades para evolucionar de monitoreo reactivo a operacion preventiva:

- Analitica de comportamiento y tendencias temporales.
- Priorizacion de eventos por severidad y contexto.
- Correlacion entre fuentes heterogeneas.
- Base para modelos predictivos de riesgo y saturacion operativa.
- Evidencia auditable para cumplimiento, respuesta y mejora continua.

## OpenSearch UI

- Dashboard: `/opensearch/`
- Discovery: `/opensearch/discover/`
- Filtros include/exclude por atributo.
- Manejo de campos vacios `(empty)`.
- Show/Hide dinamico de columnas.
- Timeline + tabla de eventos de alta densidad.

## Inicio rapido

1. Crear y activar entorno virtual.
2. Instalar dependencias.
3. Configurar BD principal Django en `CORE/settings.py`.
4. Configurar BD dedicada de logs (`opensearch`).
5. Ejecutar migraciones y levantar Django.
6. Instalar/iniciar servicio OpenSearch y agente.

```bash
python manage.py migrate
python manage.py runserver 0.0.0.0:8000
```

Servicio OpenSearch (Windows):

```powershell
powershell -ExecutionPolicy Bypass -File .\opensearch\service\install_windows_service.ps1
```

Agente OpenSearch (Windows):

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
