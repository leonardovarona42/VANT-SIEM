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

`/etc/vant-opensearch-agent/config.yaml`

## Tray GUI (auto-arranque)

El instalador copia `VANT-SIEM-Agent-Tray.desktop` a:

`/etc/xdg/autostart/vant-opensearch-agent-tray.desktop`

Para desactivar el tray:

```bash
sudo rm /etc/xdg/autostart/vant-opensearch-agent-tray.desktop
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
2. Reiniciar:
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
sudo systemctl status vant-opensearch-agent
sudo journalctl -u vant-opensearch-agent -f
```
