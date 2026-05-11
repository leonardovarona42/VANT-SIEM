#!/bin/bash
# Inicia todos los servicios: microservicios + web portal.
# Si el puerto 8000 ya está ocupado (ej: servicio del sistema), sale
# silenciosamente para evitar loop de reinicio.

VANT_DIR="/home/vant-siem"
VENV="$VANT_DIR/venv"
PYTHON="$VENV/bin/python"
MANAGE="$PYTHON $VANT_DIR/manage.py"
LOG_DIR="$VANT_DIR/logs/services"
LOCK_FILE="/tmp/vantsiem.lock"

mkdir -p "$LOG_DIR"

# Lock: evitar ejecución concurrente
if [ -f "$LOCK_FILE" ]; then
    OLD_PID=$(cat "$LOCK_FILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        echo "=== VANT-SIEM ya corriendo (PID $OLD_PID). Saliendo. ==="
        exit 0
    fi
    rm -f "$LOCK_FILE"
fi

# Si el puerto 8000 ya está ocupado, salir (lo tomó otro servicio)
if ss -tlnp | grep -q ':8000 '; then
    echo "=== Puerto 8000 ocupado. Saliendo. ==="
    exit 0
fi

echo $$ > "$LOCK_FILE"

SERVICES=(
  "AEGIS DLP Service:run_aegis_service:8002"
  "Inventory Service:run_inventory_service:8003"
  "Logs Service:run_logs_service:9201"
)

echo ""
echo "=== Iniciando microservicios ==="
CHILD_PIDS=()

for entry in "${SERVICES[@]}"; do
  IFS=':' read -r name cmd port <<< "$entry"
  log="$LOG_DIR/${cmd}.log"
  echo -n "  $name (port $port)... "
  $MANAGE "$cmd" --port "$port" --noreload >> "$log" 2>&1 &
  pid=$!
  CHILD_PIDS+=($pid)
  echo "PID $pid"
  sleep 1
done

echo ""
echo "=== Iniciando Web Portal (port 8000) ==="
$MANAGE runserver 0.0.0.0:8000 --noreload &
PORTAL_PID=$!
CHILD_PIDS+=($PORTAL_PID)
echo "  Web Portal PID $PORTAL_PID"

cleanup() {
  echo ""
  echo "=== Deteniendo servicios ==="
  for pid in "${CHILD_PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
    fi
  done
  rm -f "$LOCK_FILE"
  echo "=== Detenido ==="
}

trap cleanup EXIT INT TERM
wait "$PORTAL_PID"
