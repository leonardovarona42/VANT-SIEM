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
sudo systemctl status vant-opensearch-agent
sudo journalctl -u vant-opensearch-agent -f
```
