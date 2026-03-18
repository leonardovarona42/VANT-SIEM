# OpenSearch Agent Linux Packs

Directorios disponibles:

1. `debian/`
2. `ubuntu/`
3. `zentyal/`

Cada directorio incluye:

1. `README.md` con guia del sistema.
2. `config.yaml` base para ese OS.
3. `install_agent.sh` para instalar agente + servicio systemd.
4. `enable_logs.sh` para preparar rutas y configuraciones base de logs.
5. `VANT-SIEM-Agent-Tray.desktop` para auto-arranque del tray (GUI).

La instalacion en Linux ahora incluye un asistente CLI similar al UI de Windows.
Si quieres forzar el asistente, ejecuta:

```bash
sudo VANT_AGENT_WIZARD=1 ./install_agent.sh
```

Para desactivar el asistente (modo no interactivo):

```bash
sudo VANT_AGENT_WIZARD=0 ./install_agent.sh
```

Notas:
1. El instalador agrega `python3-pyqt6` y crea un `venv` con `--system-site-packages`
   para que el tray pueda usar PyQt6 desde el sistema.
2. El tray GUI se auto-arranca copiando el `.desktop` a `/etc/xdg/autostart/`.
   Para desactivarlo, elimina `/etc/xdg/autostart/vant-opensearch-agent-tray.desktop`.
