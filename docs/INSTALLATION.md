# Instalacion VANT-SIEM + OpenSearch

## Requisitos

- Python 3.13+
- PostgreSQL 14+
- Windows/Linux (soporte para agente en ambos)

## 1) SIEM Django

```bash
python -m venv venv
# Linux: source venv/bin/activate
# Windows: .\\venv\\Scripts\\activate
pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver 0.0.0.0:8000
```

Configurar BD principal en `CORE/settings.py`.

## 2) Base de datos dedicada OpenSearch

Crear DB separada para logs (ejemplo `opensearch`) y aplicar schema:

```bash
psql -U postgres -d opensearch -f opensearch/service/schema.sql
```

Variables recomendadas del servicio:

- `OS_DB_HOST`
- `OS_DB_PORT`
- `OS_DB_NAME`
- `OS_DB_USER`
- `OS_DB_PASSWORD`

## 3) Servicio OpenSearch (Windows)

Instalar tarea/servicio:

```powershell
powershell -ExecutionPolicy Bypass -File .\opensearch\service\install_windows_service.ps1
```

Validar health:

```powershell
Invoke-RestMethod http://127.0.0.1:9201/health
```

## 4) Agente OpenSearch

### Windows (installer)

```powershell
powershell -ExecutionPolicy Bypass -File .\dist\opensearch-agent-installer\package\Install-OpenSearchAgent.ps1 -RunNow
```

Configurar `config.yaml` (host, puerto, auth, tls, fuentes).

### Linux

Ver guias por distro en:
- `opensearch/agent/linux/debian/README.md`
- `opensearch/agent/linux/ubuntu/README.md`
- `opensearch/agent/linux/zentyal/README.md`

## 5) OpenSearch UI

Accesos:
- Dashboard: `http://<host>:8000/opensearch/`
- Discovery: `http://<host>:8000/opensearch/discover/`

## Verificacion rapida

1. El servicio responde en `/health`.
2. El agente esta en ejecucion.
3. `os_events_raw` incrementa registros.
4. Discovery muestra datos y filtros funcionales.
