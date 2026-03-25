# Windows Agent Setup

Este directorio contiene el flujo de empaquetado e instalacion del agente para Windows.

## Artefacto final

- `opensearch_agent_setup.exe`

## Build

```powershell
powershell -ExecutionPolicy Bypass -File .\opensearch_agents\windows\build_setup.ps1
```

## Contenido

- `agent_setup_ui.py`: instalador grafico PyQt6
- `Install-OpenSearchAgent.ps1`: instalacion del agente en el host
- `Uninstall-OpenSearchAgent.ps1`: desinstalacion
- `configs/`: plantillas de configuracion Windows
- `package/`: payload preparado para el setup
- `vant-opensearch-agent-tray.exe`: icono y controles de bandeja del sistema

## Capacidades incluidas

- Perfil de auditoria para Active Directory en Windows Server.
- Microservicio `asset_audit` para inventario y timeline del endpoint.
- Microservicio `aegis_dlp` para deteccion de informacion clasificada y sensible.
- El instalador crea un acceso directo en `Startup` para lanzar el tray al iniciar sesion.
