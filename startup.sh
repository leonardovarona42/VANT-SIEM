#!/bin/bash

VANT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$VANT_DIR/venv"
PYTHON="$VENV/bin/python"
CELERY="$VENV/bin/celery"

if [ ! -f "$PYTHON" ]; then
    echo "Error: Python not found at $PYTHON"
    echo "Make sure you have a virtualenv in $VENV"
    exit 1
fi

cd "$VANT_DIR"

echo "========================================"
echo " VANT-SIEM Microservices"
echo "========================================"
echo ""

PIDS=()

start_service() {
    local name="$1"
    shift
    echo "[*] Starting $name..."
    $PYTHON "$@" &
    PIDS+=($!)
    sleep 2
}

start_celery() {
    local name="$1"
    shift
    echo "[*] Starting $name..."
    $CELERY "$@" &
    PIDS+=($!)
    sleep 2
}

start_service "Logs Service (port 9201)" \
    manage.py run_opensearch_service --host 0.0.0.0 --port 9201

start_service "Incidents Service (port 8001)" \
    manage.py run_incidents_service --host 0.0.0.0 --port 8001

start_service "Assets Service (port 8002)" \
    manage.py run_assets_service --host 0.0.0.0 --port 8002

start_service "Network Service (port 8004)" \
    manage.py run_network_service --host 0.0.0.0 --port 8004

start_service "AI Service (port 8003)" \
    manage.py runserver 0.0.0.0:8003 --noreload

start_service "Web Portal (port 8000)" \
    manage.py runserver 0.0.0.0:8000 --noreload

start_celery "Celery Worker" \
    -A CORE worker --loglevel=info --concurrency=4

start_celery "Celery Beat" \
    -A CORE beat --loglevel=info

echo ""
echo "========================================"
echo " All services started!"
echo "========================================"
echo " Web Portal:        http://localhost:8000"
echo " Logs Service:      http://localhost:9201"
echo " Incidents Service: http://localhost:8001"
echo " Assets Service:    http://localhost:8002"
echo " Network Service:   http://localhost:8004"
echo " AI Service:        http://localhost:8003"
echo " Redis:             localhost:6379"
echo "========================================"
echo ""
echo "Press Ctrl+C to stop all services..."
echo ""

trap cleanup EXIT INT TERM

cleanup() {
    echo ""
    echo "Stopping all services..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null
    done
    wait
    echo "All services stopped."
}

wait
