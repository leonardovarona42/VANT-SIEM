#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENTS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_DIR="$(cd "${AGENTS_DIR}/.." && pwd)"
DIST_DIR="${SCRIPT_DIR}/dist"
BUILD_ROOT="${DIST_DIR}/.build"
AGENT_VERSION="${AGENT_VERSION:-1.0.0}"
BUILD_TS="$(date -u +"%Y%m%d%H%M%S")"
BUILD_DEB=0
BUILD_TARBALL=1
TARGET_DISTROS=()

log() { printf '%s\n' "$*"; }
info() { printf '  [info] %s\n' "$*"; }
ok() { printf '  [ok] %s\n' "$*"; }
warn() { printf '  [warn] %s\n' "$*"; }
die() { printf '  [error] %s\n' "$*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

usage() {
  cat <<'EOF'
Usage: build_linux.sh [options]

Options:
  --all             Build all detected Linux distros (default)
  --distro NAME     Build one distro: debian, ubuntu, zentyal, ...
  --deb             Also build a .deb package when dpkg-deb is available
  --no-tarball      Skip the tar.gz bundle
  --clean           Remove linux/dist and exit
  --help            Show this help
EOF
}

discover_distros() {
  local distro_dir
  for distro_dir in "${SCRIPT_DIR}"/*; do
    [[ -d "${distro_dir}" ]] || continue
    case "$(basename "${distro_dir}")" in
      common|dist) continue ;;
    esac
    [[ -f "${distro_dir}/config.yaml" ]] || continue
    TARGET_DISTROS+=("$(basename "${distro_dir}")")
  done
}

copy_tree() {
  local src="$1"
  local dst="$2"
  if [[ -d "${src}" ]]; then
    mkdir -p "${dst}"
    cp -R "${src}/." "${dst}/"
  elif [[ -f "${src}" ]]; then
    mkdir -p "$(dirname "${dst}")"
    cp "${src}" "${dst}"
  fi
}

prepare_venv() {
  local venv_dir="$1"
  python3 -m venv "${venv_dir}"
  # shellcheck disable=SC1091
  source "${venv_dir}/bin/activate"
  pip install --upgrade pip >/dev/null
  pip install pyyaml requests PyQt6 >/dev/null
  deactivate
}

write_install_script() {
  local package_dir="$1"
  cat > "${package_dir}/install.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

INSTALL_SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_ROOT="/opt/vant-siem-agent"
TARGET_CFG_DIR="/etc/vant-siem"
TARGET_LOG_DIR="/var/log/vant-siem"
TRAY_DESKTOP_SRC="${INSTALL_SOURCE}/desktop/vant-siem-agent-tray.desktop"
TRAY_DESKTOP_DST="/etc/xdg/autostart/vant-siem-agent-tray.desktop"
SERVICE_SRC="${INSTALL_SOURCE}/systemd/vant-siem-agent.service"
SERVICE_DST="/etc/systemd/system/vant-siem-agent.service"

mkdir -p "${TARGET_ROOT}" "${TARGET_CFG_DIR}" "${TARGET_LOG_DIR}" /etc/xdg/autostart
mkdir -p "${TARGET_ROOT}/scripts" "${TARGET_ROOT}/docs"
cp -a "${INSTALL_SOURCE}/agent/." "${TARGET_ROOT}/"
cp "${INSTALL_SOURCE}/config/agent.yaml" "${TARGET_CFG_DIR}/config.yaml"
cp "${INSTALL_SOURCE}/uninstall.sh" "${TARGET_ROOT}/uninstall.sh"

if [[ -d "${INSTALL_SOURCE}/scripts" ]]; then
  cp -a "${INSTALL_SOURCE}/scripts/." "${TARGET_ROOT}/scripts/"
fi
if [[ -d "${INSTALL_SOURCE}/docs" ]]; then
  cp -a "${INSTALL_SOURCE}/docs/." "${TARGET_ROOT}/docs/"
fi

if [[ -f "${TRAY_DESKTOP_SRC}" ]]; then
  cp "${TRAY_DESKTOP_SRC}" "${TRAY_DESKTOP_DST}"
fi
if [[ -f "${SERVICE_SRC}" ]]; then
  cp "${SERVICE_SRC}" "${SERVICE_DST}"
fi

chmod +x "${TARGET_ROOT}/agent.py" 2>/dev/null || true
  chmod +x "${TARGET_ROOT}/agent_tray.py" 2>/dev/null || true
  chmod +x "${TARGET_ROOT}/opensearchcheck.py" 2>/dev/null || true
  chmod +x "${TARGET_ROOT}/opensearchmover.py" 2>/dev/null || true
  chmod +x "${TARGET_ROOT}/uninstall.sh" 2>/dev/null || true
  chmod +x "${TARGET_ROOT}/scripts/"*.sh 2>/dev/null || true
  chmod +x "${TARGET_ROOT}/venv/bin/"* 2>/dev/null || true

if command -v systemctl >/dev/null 2>&1 && [[ -f "${SERVICE_DST}" ]]; then
  systemctl daemon-reload || true
  systemctl enable vant-siem-agent.service || true
  systemctl restart vant-siem-agent.service || true
fi

echo "Installed VANT-SIEM Linux agent into ${TARGET_ROOT}"
echo "Config: ${TARGET_CFG_DIR}/config.yaml"
echo "Service: ${SERVICE_DST}"
EOF
  chmod +x "${package_dir}/install.sh"
}

write_uninstall_script() {
  local package_dir="$1"
  cat > "${package_dir}/uninstall.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if command -v systemctl >/dev/null 2>&1; then
  systemctl stop vant-siem-agent.service 2>/dev/null || true
  systemctl disable vant-siem-agent.service 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
fi

rm -rf /opt/vant-siem-agent
rm -f /etc/vant-siem/config.yaml
rm -f /etc/systemd/system/vant-siem-agent.service
rm -f /etc/xdg/autostart/vant-siem-agent-tray.desktop
echo "VANT-SIEM Linux agent removed."
EOF
  chmod +x "${package_dir}/uninstall.sh"
}

stage_bundle() {
  local distro="$1"
  local distro_dir="${SCRIPT_DIR}/${distro}"
  local stage_root="${DIST_DIR}/${distro}/vant-siem-agent-install"
  local build_root="${BUILD_ROOT}/${distro}"
  local venv_dir="${build_root}/venv"
  local deb_dir="${DIST_DIR}/${distro}/deb-root"

  [[ -f "${distro_dir}/config.yaml" ]] || die "Missing config for distro: ${distro}"

  rm -rf "${stage_root}" "${build_root}" "${deb_dir}"
  mkdir -p "${stage_root}/agent" "${stage_root}/config" "${stage_root}/scripts" \
    "${stage_root}/docs" "${stage_root}/desktop" "${stage_root}/systemd" "${build_root}"

  info "Creating virtualenv for ${distro}"
  prepare_venv "${venv_dir}"

  info "Copying runtime files for ${distro}"
  copy_tree "${AGENTS_DIR}/agent.py" "${stage_root}/agent/agent.py"
  copy_tree "${AGENTS_DIR}/agent_tray.py" "${stage_root}/agent/agent_tray.py"
  copy_tree "${AGENTS_DIR}/collectors" "${stage_root}/agent/collectors"
  copy_tree "${AGENTS_DIR}/services" "${stage_root}/agent/services"
  copy_tree "${AGENTS_DIR}/output.py" "${stage_root}/agent/output.py"
  copy_tree "${AGENTS_DIR}/opensearchcheck.py" "${stage_root}/agent/opensearchcheck.py"
  copy_tree "${AGENTS_DIR}/opensearchmover.py" "${stage_root}/agent/opensearchmover.py"
  copy_tree "${AGENTS_DIR}/requirements.txt" "${stage_root}/agent/requirements.txt"
  copy_tree "${AGENTS_DIR}/linux/common/agent_installer_cli.py" "${stage_root}/scripts/agent_installer_cli.py"
  copy_tree "${AGENTS_DIR}/linux/${distro}/enable_logs.sh" "${stage_root}/scripts/enable_logs.sh"
  copy_tree "${AGENTS_DIR}/linux/common/VANT-SIEM-Agent-Tray.desktop" "${stage_root}/desktop/vant-siem-agent-tray.desktop"
  copy_tree "${AGENTS_DIR}/linux/${distro}/README.md" "${stage_root}/docs/README-${distro}.md"
  copy_tree "${AGENTS_DIR}/linux/README.md" "${stage_root}/docs/README.md"
  copy_tree "${AGENTS_DIR}/linux/OFFLINE_PACKAGING.md" "${stage_root}/docs/OFFLINE_PACKAGING.md"
  copy_tree "${AGENTS_DIR}/AGENT_MANUAL.md" "${stage_root}/docs/AGENT_MANUAL.md"
  copy_tree "${REPO_DIR}/staticfiles/img/logo.png" "${stage_root}/agent/staticfiles/img/logo.png"
  copy_tree "${venv_dir}" "${stage_root}/agent/venv"
  copy_tree "${distro_dir}/config.yaml" "${stage_root}/config/agent.yaml"

  cat > "${stage_root}/systemd/vant-siem-agent.service" <<'EOF'
[Unit]
Description=VANT-SIEM Linux Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/vant-siem-agent
ExecStart=/opt/vant-siem-agent/venv/bin/python /opt/vant-siem-agent/agent.py --config /etc/vant-siem/config.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  write_install_script "${stage_root}"
  write_uninstall_script "${stage_root}"

  cat > "${DIST_DIR}/${distro}/install.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

PACKAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/vant-siem-agent-install"
if [[ ! -f "${PACKAGE_DIR}/install.sh" ]]; then
  echo "Offline package not found: ${PACKAGE_DIR}"
  exit 1
fi

chmod +x "${PACKAGE_DIR}/install.sh"
(cd "${PACKAGE_DIR}" && bash "./install.sh")
EOF
  chmod +x "${DIST_DIR}/${distro}/install.sh"

  cat > "${DIST_DIR}/${distro}/uninstall.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ -x /opt/vant-siem-agent/uninstall.sh ]]; then
  /opt/vant-siem-agent/uninstall.sh
  exit 0
fi

PACKAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/vant-siem-agent-install"
if [[ -x "${PACKAGE_DIR}/uninstall.sh" ]]; then
  (cd "${PACKAGE_DIR}" && bash "./uninstall.sh")
  exit 0
fi

echo "Uninstall script not found."
exit 1
EOF
  chmod +x "${DIST_DIR}/${distro}/uninstall.sh"

  cat > "${stage_root}/manifest.json" <<EOF
{
  "distro": "${distro}",
  "version": "${AGENT_VERSION}",
  "build_timestamp_utc": "${BUILD_TS}",
  "package": "vant-siem-agent-install"
}
EOF

  info "Validating bundle structure for ${distro}"
  local required=(
    "${stage_root}/install.sh"
    "${stage_root}/uninstall.sh"
    "${stage_root}/config/agent.yaml"
    "${stage_root}/agent/agent.py"
    "${stage_root}/agent/agent_tray.py"
    "${stage_root}/agent/venv/bin/python"
    "${stage_root}/scripts/enable_logs.sh"
    "${stage_root}/desktop/vant-siem-agent-tray.desktop"
    "${stage_root}/systemd/vant-siem-agent.service"
  )
  local item
  for item in "${required[@]}"; do
    [[ -e "${item}" ]] || die "Missing required bundle file: ${item}"
  done

  bash -n "${stage_root}/install.sh"
  bash -n "${stage_root}/uninstall.sh"
  bash -n "${stage_root}/scripts/enable_logs.sh"

  "${venv_dir}/bin/python" - <<PY
from pathlib import Path
import yaml

cfg = yaml.safe_load(Path(r"${stage_root}/config/agent.yaml").read_text(encoding="utf-8"))
assert isinstance(cfg, dict)
assert "agent" in cfg and "output" in cfg and "control" in cfg
assert "aegis_dlp" in cfg and "collectors" in cfg
print("YAML validation ok for ${distro}")
PY

  if [[ "${BUILD_DEB}" -eq 1 ]] && command -v dpkg-deb >/dev/null 2>&1; then
    info "Creating .deb layout for ${distro}"
    mkdir -p "${deb_dir}/opt/vant-siem-agent" "${deb_dir}/etc/vant-siem" "${deb_dir}/etc/xdg/autostart" \
      "${deb_dir}/usr/local/bin" "${deb_dir}/lib/systemd/system"
    cp -a "${stage_root}/agent/." "${deb_dir}/opt/vant-siem-agent/"
    cp "${stage_root}/config/agent.yaml" "${deb_dir}/etc/vant-siem/config.yaml"
    cp "${stage_root}/desktop/vant-siem-agent-tray.desktop" "${deb_dir}/etc/xdg/autostart/vant-siem-agent-tray.desktop"
    cp "${stage_root}/systemd/vant-siem-agent.service" "${deb_dir}/lib/systemd/system/vant-siem-agent.service"
    cp "${stage_root}/scripts/enable_logs.sh" "${deb_dir}/usr/local/bin/vant-siem-enable-logs.sh"
    chmod +x "${deb_dir}/usr/local/bin/vant-siem-enable-logs.sh"
    mkdir -p "${deb_dir}/DEBIAN"
    cat > "${deb_dir}/DEBIAN/control" <<EOF
Package: vant-siem-agent
Version: ${AGENT_VERSION}
Section: net
Priority: optional
Architecture: all
Maintainer: Leonardo L. Varona Tabares <leonardovarona42@gmail.com>
Description: VANT-SIEM OpenSearch agent for offline Linux deployments
EOF
    cat > "${deb_dir}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  systemctl enable --now vant-siem-agent.service || true
fi
exit 0
EOF
    chmod 755 "${deb_dir}/DEBIAN/postinst"
    dpkg-deb --build "${deb_dir}" "${DIST_DIR}/vant-siem-agent-${distro}_${AGENT_VERSION}_all.deb" >/dev/null
    ok "Built .deb for ${distro}"
  fi

  if [[ "${BUILD_TARBALL}" -eq 1 ]]; then
    (cd "${DIST_DIR}/${distro}" && tar -czf "${DIST_DIR}/vant-siem-agent-linux-${distro}-${AGENT_VERSION}.tar.gz" vant-siem-agent-install)
    ok "Built tarball for ${distro}"
  fi

  ok "Bundle staged at ${stage_root}"
}

main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --all)
        shift
        ;;
      --distro)
        [[ $# -ge 2 ]] || die "--distro requires a value"
        TARGET_DISTROS+=("$2")
        shift 2
        ;;
      --deb)
        BUILD_DEB=1
        shift
        ;;
      --no-tarball)
        BUILD_TARBALL=0
        shift
        ;;
      --clean)
        rm -rf "${DIST_DIR}"
        ok "Removed ${DIST_DIR}"
        exit 0
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        die "Unknown option: $1"
        ;;
    esac
  done

  need_cmd python3
  need_cmd tar
  if [[ "${BUILD_DEB}" -eq 1 ]] && ! command -v dpkg-deb >/dev/null 2>&1; then
    warn "dpkg-deb not found; continuing with tarballs only"
    BUILD_DEB=0
  fi

  if [[ ${#TARGET_DISTROS[@]} -eq 0 ]]; then
    if [[ -n "${VANT_LINUX_DISTRO:-}" ]]; then
      TARGET_DISTROS+=("${VANT_LINUX_DISTRO}")
    else
      discover_distros
    fi
  fi

  [[ ${#TARGET_DISTROS[@]} -gt 0 ]] || die "No Linux distros found under ${SCRIPT_DIR}"

  mkdir -p "${DIST_DIR}"
  log "VANT-SIEM Linux packaging"
  info "Target distros: ${TARGET_DISTROS[*]}"
  info "Output directory: ${DIST_DIR}"

  local distro
  for distro in "${TARGET_DISTROS[@]}"; do
    stage_bundle "${distro}"
  done

  ok "Linux packaging finished"
}

main "$@"
