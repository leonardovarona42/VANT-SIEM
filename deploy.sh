#!/bin/bash
set -e

VANT_WSL=/home/vant-siem
VANT_WIN=/mnt/c/Users/SysAdmin/Documents/develop/VANT-SIEM
VENV=$VANT_WSL/venv

echo "=== 1. Syncing project files ==="
rsync -av --delete \
  --exclude='.git/' \
  --exclude='__pycache__/' \
  --exclude='venv/' \
  --exclude='.venv-wsl/' \
  --exclude='media/' \
  --exclude='staticfiles/' \
  --exclude='*.pyc' \
  --exclude='vant-agent.log' \
  "$VANT_WIN/" "$VANT_WSL/"

echo ""
echo "=== 2. Installing gunicorn ==="
$VENV/bin/pip install gunicorn

echo ""
echo "=== 3. Updating systemd service ==="
sudo tee /etc/systemd/system/vantsiem.service > /dev/null << 'SERVICEEOF'
[Unit]
Description=VANT-SIEM Django Application (Gunicorn)
After=network.target postgresql.service redis-server.service
Requires=postgresql.service redis-server.service

[Service]
Type=simple
User=vant-siem
WorkingDirectory=/home/vant-siem
Environment=PATH=/home/vant-siem/venv/bin:/usr/bin:/bin
Environment=TIMESCALEDB_ENABLED=True
ExecStart=/home/vant-siem/venv/bin/gunicorn --config /home/vant-siem/gunicorn.conf.py
Restart=always
RestartSec=5
StandardOutput=append:/var/log/vantsiem.log
StandardError=append:/var/log/vantsiem.log

[Install]
WantedBy=multi-user.target
SERVICEEOF

echo ""
echo "=== 4. Reloading systemd ==="
sudo systemctl daemon-reload
sudo systemctl restart vantsiem.service

echo ""
echo "=== 5. Status ==="
sleep 2
sudo systemctl status vantsiem.service --no-pager | head -10

echo ""
echo "=== Done! ==="
