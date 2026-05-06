#!/bin/bash

echo "Stopping VANT-SIEM services..."

pkill -f "manage.py runserver" 2>/dev/null
pkill -f "manage.py run_opensearch_service" 2>/dev/null
pkill -f "manage.py run_incidents_service" 2>/dev/null
pkill -f "manage.py run_assets_service" 2>/dev/null
pkill -f "manage.py run_network_service" 2>/dev/null
pkill -f "celery -A CORE" 2>/dev/null

echo "All services stopped."
