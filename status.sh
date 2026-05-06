#!/bin/bash

echo "VANT-SIEM Services Status"
echo "========================="
echo ""

services=(
    "Web Portal:manage.py runserver 0.0.0.0:8000"
    "Logs Service:manage.py run_opensearch_service"
    "Incidents Service:manage.py run_incidents_service"
    "Assets Service:manage.py run_assets_service"
    "Network Service:manage.py run_network_service"
    "AI Service:manage.py runserver 0.0.0.0:8003"
    "Celery Worker:celery -A CORE worker"
    "Celery Beat:celery -A CORE beat"
)

for svc in "${services[@]}"; do
    name="${svc%%:*}"
    pattern="${svc##*:}"

    if pgrep -f "$pattern" > /dev/null 2>&1; then
        echo "  [OK] $name"
    else
        echo "  [--] $name"
    fi
done

echo ""
echo "Redis:"
if pgrep -f "redis-server" > /dev/null 2>&1; then
    echo "  [OK] Redis"
else
    echo "  [--] Redis (not running)"
fi
