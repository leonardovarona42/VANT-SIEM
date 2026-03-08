#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root."
  exit 1
fi

AGENT_SRC="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_DIR="/opt/vant/opensearch-agent"
CONFIG_DIR="/etc/vant-opensearch-agent"
SERVICE_NAME="vant-opensearch-agent"

apt-get update
apt-get install -y python3 python3-venv python3-pip rsync

mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}"
rsync -a --delete "${AGENT_SRC}/" "${INSTALL_DIR}/"

python3 -m venv "${INSTALL_DIR}/venv"
"${INSTALL_DIR}/venv/bin/pip" install --upgrade pip
"${INSTALL_DIR}/venv/bin/pip" install pyyaml requests

if [[ ! -f "${CONFIG_DIR}/config.yaml" ]]; then
  cp "$(dirname "$0")/config.yaml" "${CONFIG_DIR}/config.yaml"
fi

cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=VANT OpenSearch Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/python ${INSTALL_DIR}/agent.py --config ${CONFIG_DIR}/config.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}"
systemctl status "${SERVICE_NAME}" --no-pager

echo "Installed. Edit config at: ${CONFIG_DIR}/config.yaml"
