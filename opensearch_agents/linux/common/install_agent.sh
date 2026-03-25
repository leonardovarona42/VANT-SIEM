#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root."
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINUX_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${LINUX_DIR}/dist"
DISTRO="${VANT_LINUX_DISTRO:-${DISTRO:-}}"

if [[ -z "${DISTRO}" ]]; then
  echo "Set VANT_LINUX_DISTRO to debian, ubuntu or zentyal."
  exit 1
fi

find_package_dir() {
  local candidate
  if [[ ! -d "${DIST_DIR}" ]]; then
    return 1
  fi
  candidate="$(find "${DIST_DIR}" -maxdepth 1 -type d -name "vant-siem-agent-install" | head -n 1)"
  if [[ -n "${candidate}" ]]; then
    echo "${candidate}"
    return 0
  fi
  return 1
}

extract_package_tarball() {
  local tarball workdir extracted
  if [[ ! -d "${DIST_DIR}" ]]; then
    return 1
  fi
  tarball="$(find "${DIST_DIR}" -maxdepth 1 -type f -name "vant-siem-agent-linux-${DISTRO}-*.tar.gz" | head -n 1)"
  if [[ -z "${tarball}" ]]; then
    return 1
  fi

  workdir="$(mktemp -d /tmp/vant-siem-agent-linux.XXXXXX)"
  tar -xzf "${tarball}" -C "${workdir}"
  extracted="$(find "${workdir}" -maxdepth 1 -type d -name "vant-siem-agent-install" | head -n 1)"
  if [[ -z "${extracted}" ]]; then
    echo "Failed to extract package payload from ${tarball}"
    exit 1
  fi
  echo "${extracted}"
}

PACKAGE_DIR=""
if PACKAGE_DIR="$(find_package_dir)"; then
  :
elif PACKAGE_DIR="$(extract_package_tarball)"; then
  :
else
  echo "Offline package not found under ${DIST_DIR}."
  echo "Build it first with: ./opensearch_agents/build_linux.sh"
  exit 1
fi

INSTALL_SCRIPT="${PACKAGE_DIR}/install.sh"
if [[ ! -f "${INSTALL_SCRIPT}" ]]; then
  echo "Install script not found in package: ${INSTALL_SCRIPT}"
  exit 1
fi

if [[ -t 0 && "${VANT_AGENT_WIZARD:-1}" != "0" ]]; then
  TEMPLATE_PATH="${PACKAGE_DIR}/config/agent.yaml"
  CONFIG_PATH="${PACKAGE_DIR}/config/agent.yaml"
  WIZARD_BIN="${SCRIPT_DIR}/agent_installer_cli.py"
  VENV_PYTHON="${PACKAGE_DIR}/agent/venv/bin/python"

  if [[ -x "${VENV_PYTHON}" && -f "${WIZARD_BIN}" ]]; then
    "${VENV_PYTHON}" "${WIZARD_BIN}" \
      --config "${CONFIG_PATH}" \
      --template "${TEMPLATE_PATH}"
  else
    echo "Wizard unavailable in offline package; using bundled defaults."
  fi
fi

chmod +x "${INSTALL_SCRIPT}"
(cd "${PACKAGE_DIR}" && bash "./install.sh")

echo "Installed from offline package: ${PACKAGE_DIR}"
echo "Edit /etc/vant-siem/config.yaml to adjust the agent."
