# Windows Agent Setup

Este directorio contiene el flujo de empaquetado e instalacion del agente para Windows.

## Artefacto final

- `opensearch_agent_setup.exe`

## Build

```powershell
powershell -ExecutionPolicy Bypass -File .\opensearch_agents\windows\build_setup.ps1
```

Si `opensearch_agent_setup.exe` esta en uso, el build deja una copia nueva con timestamp.

## Contenido

- `agent_setup_ui.py`: instalador grafico PyQt6
- `Install-OpenSearchAgent.ps1`: instalacion del agente en el host
- `Uninstall-OpenSearchAgent.ps1`: desinstalacion
- `configs/`: plantillas de configuracion Windows
- `package/`: payload preparado para el setup
- `vant-opensearch-agent-tray.exe`: icono y controles de bandeja del sistema
- `sendheartbeat.exe`: heartbeat manual
- `opena_mover.exe`: cambio de servidor
- `opena_checker.exe`: validacion operativa
- aliases legacy: `sendhearbet.exe`, `opena_cheker.exe`

## Capacidades incluidas

- Perfil de auditoria para Active Directory en Windows Server.
- Microservicio `asset_audit` para inventario y timeline del endpoint.
- Microservicio `aegis_dlp` para deteccion de informacion clasificada y sensible.
- Enrolamiento y validacion de token desde el boton `Probar conexion`.
- El instalador crea un acceso directo en `Startup` para lanzar el tray al iniciar sesion.
- El instalador registra desinstalacion en Windows.
- El directorio de instalacion aplica ACL endurecida y guarda metadata del owner.

## Flujo del setup

1. Genera `config.yaml` desde el wizard.
2. Ejecuta `Probar conexion` para bootstrap, enroll y token.
3. Copia el payload en el host.
4. Registra la tarea programada del agente.
5. Instala tray, desinstalador y utilidades auxiliares.

## Desinstalacion

Opciones disponibles:

- `Uninstall-OpenSearchAgent.ps1`
- `Uninstall-VANT-OpenSearch-Agent.cmd`
- Entrada en "Apps & Features"
