#!/bin/bash
# VANT-SIEM Disk Monitoring Script
# Alerts the event bus when disk usage exceeds a threshold

THRESHOLD=80
BUS_URL="http://127.0.0.1:8600/api/events/receive/"
SERVICE_SECRET="changeme-service-secret" # Should be loaded from .env in real deploy

# Get current disk usage of root partition
USAGE=$(df / | grep / | awk '{ print $5 }' | sed 's/%//')

if [ "$USAGE" -gt "$THRESHOLD" ]; then
    echo "Disk usage critical: ${USAGE}%"

    # Construct JSON payload
    PAYLOAD=$(cat <<EOF
{
    "event_type": "disk_alert",
    "source_service": "system_monitor",
    "entity_type": "server",
    "payload": {
        "usage": "${USAGE}%",
        "threshold": "${THRESHOLD}%",
        "partition": "/"
    },
    "severity": "critical"
}
EOF
)

    # Send to vant-bus
    curl -s -X POST "$BUS_URL" \
         -H "Content-Type: application/json" \
         -H "X-Service-Secret: $SERVICE_SECRET" \
         -d "$PAYLOAD" > /dev/null
fi
