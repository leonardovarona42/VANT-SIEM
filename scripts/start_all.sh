#!/bin/bash
# VANT-SIEM Microservices — Start All Services
set -e

SERVICES_DIR="/opt/vant-siem/services"
LOG_DIR="/var/log/vant"
VENV="/opt/vant-siem/venv"

mkdir -p "$LOG_DIR"

echo "=== VANT-SIEM Microservices Starting ==="

for svc in vant-auth vant-web vant-inventory vant-logs vant-aegis vant-bus vant-intelligence; do
    echo "Starting $svc..."
    systemctl start "vantsiem-${svc#vant-}" 2>/dev/null || \
    sudo -u leonardo "$VENV/bin/gunicorn" \
        --config "$SERVICES_DIR/$svc/gunicorn.conf.py" \
        --daemon --pid "/run/vantsiem-${svc#vant-}.pid"
    echo "  $svc started"
done

echo "=== All services started ==="
systemctl status vantsiem-* --no-pager 2>/dev/null || true
