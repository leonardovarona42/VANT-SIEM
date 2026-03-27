# Ubuntu Agent Pack

## 1) Instalar agente

```bash
cd opensearch_agents/linux/ubuntu
sudo chmod +x install_agent.sh enable_logs.sh
sudo ./install_agent.sh
```

Para forzar el asistente CLI (similar al UI de Windows):

```bash
sudo VANT_AGENT_WIZARD=1 ./install_agent.sh
```

Para desactivar el asistente (modo no interactivo):

```bash
sudo VANT_AGENT_WIZARD=0 ./install_agent.sh
```

Config principal:

`/etc/vant-siem/config.yaml`

La instalacion usa el bundle offline generado en `linux/dist/ubuntu/vant-siem-agent-install/`.
Tambien puedes ejecutar directamente `linux/dist/ubuntu/install.sh`.
Primero ejecuta `opensearch_agents/linux/build_linux.sh` en la maquina de empaquetado.
No hace `apt` ni `pip` en la maquina destino.
Si necesitas instalar desde un directorio ya extraido, usa `VANT_AGENT_PACKAGE_DIR`.

## Tray GUI (auto-arranque)

El instalador compartido copia `../common/VANT-SIEM-Agent-Tray.desktop` a:

`/etc/xdg/autostart/vant-siem-agent-tray.desktop`

La instalacion no descarga nada: usa el paquete ya generado en
`linux/dist/ubuntu/` y ejecuta su `install.sh`.

Ese bundle ya incluye `services/audit_inventory.py` y `services/aegis_dlp.py`.
El inventario deja una linea de tiempo de hardware, software, red, USB y usuarios.
El modulo DLP revisa rutas locales y genera incidentes sin depender de internet.
Tambien incluye `sendheartbeat`, `opena_mover` y `opena_checker` en
`/opt/vant-siem-agent/bin` con atajos en `/usr/local/bin`.
Durante la instalacion, `/opt/vant-siem-agent` queda asignado al usuario que
ejecuto `sudo` cuando esa identidad esta disponible.

Para desactivar el tray:

```bash
sudo rm /etc/xdg/autostart/vant-siem-agent-tray.desktop
```

## 2) Habilitar fuentes de logs

```bash
sudo ./enable_logs.sh
```

### Snort

1. En `snort.conf`, habilitar:
```conf
output alert_fast: /var/log/snort/alert
```
2. Reiniciar `snort`.

### Suricata

1. En `/etc/suricata/suricata.yaml`, validar `eve-log` hacia `/var/log/suricata/eve.json`.
2. Reiniciar `suricata`.

### PostgreSQL

1. En `postgresql.conf`:
```conf
logging_collector = on
log_statement = 'all'
```
2. Reiniciar PostgreSQL.
3. Ajustar `collectors.postgres.path` si cambia nombre del archivo.

### Samba / AD

1. Si Ubuntu actua como AD DC con Samba, habilitar auditoria en `smb.conf` con `vfs_full_audit`.
2. Guardar auditoria en `/var/log/samba/audit.log`.
3. Activar entrada `file_logs` para ese archivo.

## 3) Verificar

```bash
sudo systemctl status vant-siem-agent
sudo journalctl -u vant-siem-agent -f
```
