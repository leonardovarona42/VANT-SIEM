# Linux Packs

La estructura Linux queda separada asi:

1. `common/` para assets y logica compartida.
2. `debian/` para defaults y guia de Debian.
3. `ubuntu/` para defaults y guia de Ubuntu.
4. `zentyal/` para defaults y guia de Zentyal/Samba AD.

El instalador compartido vive en `common/install_agent.sh` y cada distro solo
define su wrapper, su `config.yaml` y su guia operativa.
Ese wrapper espera que primero se haya generado el bundle con
`opensearch_agents/build_linux.sh`.

La instalacion en destino es offline: el script busca un paquete ya construido
en `linux/dist/` y ejecuta el `install.sh` incluido en ese paquete.

Ese instalador ya no descarga nada en la maquina destino. Solo ejecuta el
bundle offline generado en `linux/dist/vant-siem-agent-install/`, que incluye
el tray GUI, el venv, `services/` y los scripts necesarios.

El agente Linux ya sale preparado con dos microservicios internos:

1. `audit_inventory` para inventario de hardware, software, red, USB y usuarios.
2. `aegis_dlp` para inspeccion DLP offline basada en rutas locales y reglas.

El tray GUI tambien es compartido y queda en `common/VANT-SIEM-Agent-Tray.desktop`.
El instalador lo copia automaticamente a:

`/etc/xdg/autostart/vant-siem-agent-tray.desktop`

Los artefactos generados por `build_linux.sh` quedan en `linux/dist/`.
Ese directorio debe copiarse junto al instalador cuando se despliega en una
maquina sin acceso a internet.
El directorio reutilizable para instalar sin Internet es:

`linux/dist/vant-siem-agent-install/`

Para forzar el asistente CLI durante la instalacion:

```bash
sudo VANT_AGENT_WIZARD=1 ./install_agent.sh
```

Para desactivarlo:

```bash
sudo VANT_AGENT_WIZARD=0 ./install_agent.sh
```
