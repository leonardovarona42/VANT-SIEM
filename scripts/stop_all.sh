#!/bin/bash
# VANT-SIEM Microservices — Stop All Services
set -e

echo "=== VANT-SIEM Microservices Stopping ==="

for svc in auth web inventory logs aegis bus intelligence; do
    echo "Stopping vantsiem-$svc..."
    systemctl stop "vantsiem-$svc" 2>/dev/null || true
    PIDFILE="/run/vantsiem-${svc}.pid"
    if [ -f "$PIDFILE" ]; then
        kill "$(cat "$PIDFILE")" 2>/dev/null || true
        rm -f "$PIDFILE"
    fi
    echo "  vantsiem-$svc stopped"
done

echo "=== All services stopped ==="
