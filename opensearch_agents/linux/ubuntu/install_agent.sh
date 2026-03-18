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
DISTRO="ubuntu"

apt-get update
apt-get install -y python3 python3-venv python3-pip python3-pyqt6 rsync

mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}"
rsync -a --delete "${AGENT_SRC}/" "${INSTALL_DIR}/"

python3 -m venv --system-site-packages "${INSTALL_DIR}/venv"
"${INSTALL_DIR}/venv/bin/pip" install --upgrade pip
"${INSTALL_DIR}/venv/bin/pip" install pyyaml requests

TEMPLATE_PATH="${INSTALL_DIR}/linux/${DISTRO}/config.yaml"
WIZARD_BIN="${INSTALL_DIR}/installer/agent_installer_cli.py"

if [[ ! -f "${CONFIG_DIR}/config.yaml" ]]; then
  cp "$(dirname "$0")/config.yaml" "${CONFIG_DIR}/config.yaml"
fi

if [[ -t 0 && -f "${WIZARD_BIN}" ]]; then
  if [[ "${VANT_AGENT_WIZARD:-1}" != "0" ]]; then
    "${INSTALL_DIR}/venv/bin/python" "${WIZARD_BIN}" \
      --config "${CONFIG_DIR}/config.yaml" \
      --template "${TEMPLATE_PATH}"
  fi
fi

TRAY_SOURCE="${INSTALL_DIR}/linux/${DISTRO}/VANT-SIEM-Agent-Tray.desktop"
TRAY_TARGET="/etc/xdg/autostart/vant-opensearch-agent-tray.desktop"
if [[ -f "${TRAY_SOURCE}" ]]; then
  install -m 0644 "${TRAY_SOURCE}" "${TRAY_TARGET}"
fi

EXEC_START="${INSTALL_DIR}/venv/bin/python ${INSTALL_DIR}/agent.py --config ${CONFIG_DIR}/config.yaml"
if [[ -x "${INSTALL_DIR}/VANT-SIEM-Agent" ]]; then
  EXEC_START="${INSTALL_DIR}/VANT-SIEM-Agent --config ${CONFIG_DIR}/config.yaml"
fi

cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=VANT OpenSearch Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${EXEC_START}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}"
systemctl status "${SERVICE_NAME}" --no-pager

echo "Installed. Edit config at: ${CONFIG_DIR}/config.yaml"
