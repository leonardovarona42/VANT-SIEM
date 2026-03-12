#!/bin/bash
#
# ════════════════════════════════════════════════════════════════════════════
#
#                    VANT-SIEM OpenSearch Agent
#                       Linux Build Script
#
#  Script: build_linux.sh
#  Purpose: Create installation packages for Linux distributions
#
# ════════════════════════════════════════════════════════════════════════════
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="${SCRIPT_DIR}/dist"
AGENT_VERSION="1.0.0"
AGENT_NAME="vant-siem-agent"

# Print functions
print_header() {
    echo -e "\n${CYAN}${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}  $1${NC}"
    echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════════════════════${NC}\n"
}

print_success() {
    echo -e "  ${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "  ${RED}✗${NC} $1"
}

print_warning() {
    echo -e "  ${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "  ${BLUE}ℹ${NC} $1"
}

# Check dependencies
check_dependencies() {
    print_header "Checking Dependencies"
    
    local missing_deps=()
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    else
        print_success "python3: $(python3 --version)"
    fi
    
    # Check pip
    if ! command -v pip3 &> /dev/null && ! python3 -m pip --version &> /dev/null; then
        missing_deps+=("python3-pip")
    else
        print_success "pip3: installed"
    fi
    
    # Check virtualenv
    if ! python3 -c "import venv" 2>/dev/null; then
        missing_deps+=("python3-venv")
    else
        print_success "python3-venv: installed"
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing dependencies: ${missing_deps[*]}"
        print_info "Install with: sudo apt-get install ${missing_deps[*]}"
        return 1
    fi
    
    return 0
}

# Install Python dependencies
install_dependencies() {
    print_header "Installing Python Dependencies"
    
    cd "${SCRIPT_DIR}"
    
    # Check if requirements.txt exists
    if [ -f "requirements.txt" ]; then
        print_info "Installing from requirements.txt..."
        pip3 install --user -r requirements.txt
        print_success "Dependencies installed"
    else
        print_info "Installing basic dependencies..."
        pip3 install --user pyyaml requests
        print_success "Basic dependencies installed"
    fi
}

# Create virtual environment for the agent
create_venv() {
    print_header "Creating Virtual Environment"
    
    local venv_dir="${DIST_DIR}/${AGENT_NAME}-venv"
    
    # Create dist directory
    mkdir -p "${DIST_DIR}"
    
    # Create virtual environment
    python3 -m venv "${venv_dir}"
    
    # Activate and install
    source "${venv_dir}/bin/activate"
    pip install --upgrade pip
    pip install pyyaml requests
    
    # Copy agent files
    print_info "Copying agent files..."
    
    # Copy main scripts
    cp agent.py "${venv_dir}/"
    cp -r collectors "${venv_dir}/"
    cp output.py "${venv_dir}/"
    cp config.example.yaml "${venv_dir}/config.yaml"
    
    # Copy utility scripts
    cp opensearchcheck.py "${venv_dir}/"
    cp opensearchmover.py "${venv_dir}/"
    
    # Make scripts executable
    chmod +x "${venv_dir}/agent.py"
    chmod +x "${venv_dir}/opensearchcheck.py"
    chmod +x "${venv_dir}/opensearchmover.py"
    
    deactivate
    
    print_success "Virtual environment created at: ${venv_dir}"
    
    echo "${venv_dir}"
}

# Create Debian package
create_debian_package() {
    print_header "Creating Debian Package"
    
    local pkg_dir="${DIST_DIR}/${AGENT_NAME}-debian"
    local venv_dir="${DIST_DIR}/${AGENT_NAME}-venv"
    
    mkdir -p "${pkg_dir}/opt/vant-siem-agent"
    mkdir -p "${pkg_dir}/etc/vant-siem"
    mkdir -p "${pkg_dir}/var/log/vant-siem"
    mkdir -p "${pkg_dir}/DEBIAN"
    mkdir -p "${pkg_dir}/etc/init.d"
    
    # Copy agent
    cp -r "${venv_dir}"/* "${pkg_dir}/opt/vant-siem-agent/"
    
    # Copy config
    cp config.example.yaml "${pkg_dir}/etc/vant-siem/config.yaml"
    
    # Create init script
    cat > "${pkg_dir}/etc/init.d/vant-siem-agent" << 'INITEOF'
#!/bin/bash
### BEGIN INIT INFO
# Provides:          vant-siem-agent
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $network $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: VANT-SIEM OpenSearch Agent
# Description:       Security event collector for VANT-SIEM
### END INIT INFO

NAME=vant-siem-agent
DESC="VANT-SIEM OpenSearch Agent"
PIDFILE=/var/run/$NAME.pid
SCRIPT=/opt/vant-siem-agent/agent.py
PYTHON_BIN=/opt/vant-siem-agent/bin/python
CONFIG=/etc/vant-siem/config.yaml
USER=root

case "$1" in
  start)
    echo "Starting $DESC: "
    cd /opt/vant-siem-agent
    $PYTHON_BIN $SCRIPT --config $CONFIG &
    echo $! > $PIDFILE
    echo "OK"
    ;;
  stop)
    echo "Stopping $DESC: "
    if [ -f $PIDFILE ]; then
      kill $(cat $PIDFILE)
      rm $PIDFILE
    fi
    echo "OK"
    ;;
  restart)
    $0 stop
    sleep 2
    $0 start
    ;;
  status)
    if [ -f $PIDFILE ]; then
      echo "$DESC is running (PID: $(cat $PIDFILE))"
    else
      echo "$DESC is not running"
    fi
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|status}"
    exit 1
    ;;
esac

exit 0
INITEOF

    chmod +x "${pkg_dir}/etc/init.d/vant-siem-agent"
    
    # Create control file
    cat > "${pkg_dir}/DEBIAN/control" << 'CONTROLEOF'
Package: vant-siem-agent
Version: 1.0.0
Section: net
Priority: optional
Architecture: all
Depends: python3, python3-yaml, python3-requests
Maintainer: LLVT <leonardovarona42@gmail.com>
Description: VANT-SIEM OpenSearch Agent
 Security event collector for VANT-SIEM platform.
 Collects events from Snort, Suricata, Windows Event Log,
 PostgreSQL and custom file sources.
Homepage: https://github.com/vant-siem/vant-siem
CONTROLEOF

    # Build package
    print_info "Building .deb package..."
    dpkg-deb --build "${pkg_dir}" "${DIST_DIR}/vant-siem-agent_${AGENT_VERSION}_all.deb"
    
    print_success "Package created: dist/vant-siem-agent_${AGENT_VERSION}_all.deb"
}

# Create generic tarball
create_tarball() {
    print_header "Creating Tarball Package"
    
    local venv_dir="${DIST_DIR}/${AGENT_NAME}-venv"
    local tarball="${DIST_DIR}/${AGENT_NAME}-linux-${AGENT_VERSION}.tar.gz"
    
    # Create directory structure
    local install_dir="${DIST_DIR}/vant-siem-agent-install"
    rm -rf "${install_dir}"
    mkdir -p "${install_dir}/agent"
    mkdir -p "${install_dir}/config"
    mkdir -p "${install_dir}/scripts"
    mkdir -p "${install_dir}/docs"
    
    # Copy files
    cp -r "${venv_dir}"/* "${install_dir}/agent/"
    cp config.example.yaml "${install_dir}/config/agent.yaml"
    cp opensearchcheck.py "${install_dir}/scripts/"
    cp opensearchmover.py "${install_dir}/scripts/"
    cp AGENT_MANUAL.md "${install_dir}/docs/"
    
    # Create launcher script
    cat > "${install_dir}/agent/run.sh" << 'LAUNCHEREOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
PYTHON_BIN="${SCRIPT_DIR}/bin/python"
${PYTHON_BIN} agent.py --config ../config/agent.yaml "$@"
LAUNCHEREOF
    chmod +x "${install_dir}/agent/run.sh"
    
    # Create uninstaller
    cat > "${install_dir}/uninstall.sh" << 'UNINSTALLEOF'
#!/bin/bash
echo "Uninstalling VANT-SIEM Agent..."
rm -rf /opt/vant-siem-agent
rm -rf /etc/vant-siem
rm -f /var/log/vant-siem/agent.log
update-rc.d vant-siem-agent remove 2>/dev/null || true
echo "Uninstalled successfully"
UNINSTALLEOF
    chmod +x "${install_dir}/uninstall.sh"
    
    # Create installer
    cat > "${install_dir}/install.sh" << 'INSTALLEOF'
#!/bin/bash
echo "Installing VANT-SIEM Agent..."

# Create directories
mkdir -p /opt/vant-siem-agent
mkdir -p /etc/vant-siem
mkdir -p /var/log/vant-siem

# Copy files
cp -r agent/* /opt/vant-siem-agent/
cp config/agent.yaml /etc/vant-siem/config.yaml
cp scripts/*.py /opt/vant-siem-agent/

# Make executable
chmod +x /opt/vant-siem-agent/agent.py
chmod +x /opt/vant-siem-agent/opensearchcheck.py
chmod +x /opt/vant-siem-agent/opensearchmover.py
chmod +x /opt/vant-siem-agent/run.sh

echo "Installation complete!"
echo "Edit /etc/vant-siem/config.yaml to configure the agent"
echo "Run with: /opt/vant-siem-agent/run.sh"
INSTALLEOF
    chmod +x "${install_dir}/install.sh"
    
    # Create tarball
    cd "${DIST_DIR}"
    tar -czf vant-siem-agent-linux-${AGENT_VERSION}.tar.gz vant-siem-agent-install/
    
    print_success "Tarball created: dist/vant-siem-agent-linux-${AGENT_VERSION}.tar.gz"
}

# Main function
main() {
    echo -e "${CYAN}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                       ║"
    echo "║               VANT-SIEM Agent Linux Build Script                     ║"
    echo "║                     Package Builder                                 ║"
    echo "║                                                                       ║"
    echo "╚═══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo "Build started: $(date)"
    echo ""
    
    # Parse arguments
    local build_all=true
    local build_deb=false
    local build_tarball=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --deb)
                build_all=false
                build_deb=true
                shift
                ;;
            --tarball)
                build_all=false
                build_tarball=true
                shift
                ;;
            --clean)
                print_info "Cleaning dist directory..."
                rm -rf "${DIST_DIR}"
                print_success "Cleaned"
                exit 0
                ;;
            --help|-h)
                echo "Usage: $0 [options]"
                echo ""
                echo "Options:"
                echo "  --deb       Build Debian package"
                echo "  --tarball   Build tarball package"
                echo "  --clean     Clean dist directory"
                echo "  --help      Show this help"
                echo ""
                echo "Examples:"
                echo "  $0              # Build all packages"
                echo "  $0 --deb        # Build only Debian package"
                echo "  $0 --tarball    # Build only tarball"
                echo "  $0 --clean      # Clean build directory"
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                echo "Use --help for usage"
                exit 1
                ;;
        esac
    done
    
    # Check dependencies
    if ! check_dependencies; then
        exit 1
    fi
    
    # Install dependencies
    install_dependencies
    
    # Create virtual environment
    create_venv
    
    # Build packages
    if [ "$build_all" = true ] || [ "$build_deb" = true ]; then
        create_debian_package
    fi
    
    if [ "$build_all" = true ] || [ "$build_tarball" = true ]; then
        create_tarball
    fi
    
    # Summary
    print_header "Build Complete!"
    
    echo "Build finished: $(date)"
    echo ""
    echo "Output files:"
    ls -lh "${DIST_DIR}"/*.deb 2>/dev/null || true
    ls -lh "${DIST_DIR}"/*.tar.gz 2>/dev/null || true
    echo ""
    print_success "All builds completed!"
    echo ""
    echo "To install:"
    echo "  - Debian/Ubuntu: sudo dpkg -i dist/vant-siem-agent_${AGENT_VERSION}_all.deb"
    echo "  - Generic: tar -xzf dist/vant-siem-agent-linux-${AGENT_VERSION}.tar.gz && cd vant-siem-agent-install && ./install.sh"
}

# Run main
main "$@"
