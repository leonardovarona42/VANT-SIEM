# Debian Agent Pack

## 1) Instalar agente

```bash
cd opensearch_agents/linux/debian
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

La instalacion usa el bundle offline generado en `linux/dist/vant-siem-agent-install/`.
Primero ejecuta `opensearch_agents/build_linux.sh` en la maquina de empaquetado.
No hace `apt` ni `pip` en la maquina destino.
Si necesitas instalar desde un directorio ya extraido, usa `VANT_AGENT_PACKAGE_DIR`.

## Tray GUI (auto-arranque)

El instalador compartido copia `../common/VANT-SIEM-Agent-Tray.desktop` a:

`/etc/xdg/autostart/vant-siem-agent-tray.desktop`

La instalacion no descarga nada: usa el paquete ya generado en `linux/dist/`
y ejecuta su `install.sh`.

Ese bundle ya incluye `services/audit_inventory.py` y `services/aegis_dlp.py`.
El primero genera la linea de tiempo de hardware, software, red, USB y usuarios.
El segundo revisa documentos locales y dispara incidentes DLP sin depender de internet.

Para desactivar el tray:

```bash
sudo rm /etc/xdg/autostart/vant-siem-agent-tray.desktop
```

## 2) Habilitar fuentes de logs

```bash
sudo ./enable_logs.sh
```

### Snort

1. En `snort.conf`, habilitar `alert_fast` a archivo:
```conf
output alert_fast: /var/log/snort/alert
```
2. Reiniciar el servicio:
```bash
sudo systemctl restart snort
```

### Suricata

1. En `/etc/suricata/suricata.yaml`, validar:
```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
```
2. Reiniciar:
```bash
sudo systemctl restart suricata
```

### PostgreSQL

1. Editar `postgresql.conf`:
```conf
logging_collector = on
log_directory = 'log'
log_filename = 'postgresql-%Y-%m-%d.log'
log_statement = 'all'
```
2. Reiniciar PostgreSQL.
3. Ajustar `collectors.postgres.path` al archivo real en `/var/log/postgresql/`.

### Samba (si aplica)

1. Habilitar `vfs_full_audit` en `smb.conf` para escribir auditoria.
2. Enviar a `/var/log/samba/audit.log`.
3. Agregar en `collectors.file_logs.items` una entrada para ese archivo.

## 3) Estado del servicio

```bash
sudo systemctl status vant-siem-agent
sudo journalctl -u vant-siem-agent -f
```
