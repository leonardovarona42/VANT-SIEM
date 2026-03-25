# Zentyal Agent Pack (Samba AD)

## 1) Instalar agente

```bash
cd opensearch_agents/linux/zentyal
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

## Tray GUI (auto-arranque)

El instalador compartido copia `../common/VANT-SIEM-Agent-Tray.desktop` a:

`/etc/xdg/autostart/vant-siem-agent-tray.desktop`

La instalacion no descarga nada: usa el paquete ya generado en `linux/dist/`
y ejecuta su `install.sh`.

Ese bundle ya incluye `services/audit_inventory.py` y `services/aegis_dlp.py`.
Con eso el agente captura una linea de tiempo completa de activos y
documentos sensibles incluso en despliegues sin internet.

Para desactivar el tray:

```bash
sudo rm /etc/xdg/autostart/vant-siem-agent-tray.desktop
```

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
sudo systemctl status vant-siem-agent
sudo journalctl -u vant-siem-agent -f
tail -f /var/log/samba/audit.log
```
