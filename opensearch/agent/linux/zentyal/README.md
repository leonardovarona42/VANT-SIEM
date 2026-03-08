# Zentyal Agent Pack (Samba AD)

## 1) Instalar agente

```bash
cd opensearch/agent/linux/zentyal
sudo chmod +x install_agent.sh enable_logs.sh
sudo ./install_agent.sh
```

Config principal:

`/etc/vant-opensearch-agent/config.yaml`

## 2) Habilitar logs para AD Samba + extras

```bash
sudo ./enable_logs.sh
```

Este script:

1. Crea `/etc/samba/smb.conf.d/99-vant-audit.conf`.
2. Agrega include en `/etc/samba/smb.conf` (si no existe).
3. Configura `rsyslog` para enviar `local5.notice` a `/var/log/samba/audit.log`.
4. Reinicia `rsyslog` y `samba-ad-dc`/`smbd`.

## 3) Consideracion importante de Zentyal

Zentyal puede regenerar configuraciones Samba. Si eso pasa:

1. Reaplica `enable_logs.sh`.
2. O mueve estos ajustes a plantillas persistentes de Zentyal.

## 4) Otras fuentes

### PostgreSQL

1. Habilitar `logging_collector = on` en `postgresql.conf`.
2. Ajustar `collectors.postgres.path`.

### Snort/Suricata

1. Snort hacia `/var/log/snort/alert`.
2. Suricata `eve.json` en `/var/log/suricata/eve.json`.
3. Activar en `config.yaml`.

## 5) Verificar

```bash
sudo systemctl status vant-opensearch-agent
sudo journalctl -u vant-opensearch-agent -f
tail -f /var/log/samba/audit.log
```
