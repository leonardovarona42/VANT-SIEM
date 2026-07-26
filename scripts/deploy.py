#!/usr/bin/env python3
"""
VANT-SIEM Microservices — Deployment Script
Deploys all services to a remote server via paramiko.

Usage:
    python deploy.py                          # Uses defaults (192.168.12.43)
    python deploy.py --server 10.0.0.1        # Custom server
    python deploy.py --skip-env               # Skip .env upload
    python deploy.py --skip-nginx             # Skip nginx config
"""

import argparse
import os
import sys
import time
import fnmatch
from pathlib import Path, PurePosixPath

import paramiko

# ─── Configuration ───────────────────────────────────────────────────────────

DEFAULT_SERVER = "192.168.12.43"
DEFAULT_USER = "leonardo"
DEFAULT_PASSWORD = "1qazxsw2"
REMOTE_BASE = "/opt/vant-siem"
LOG_DIR = "/var/log/vant"
SERVICES = ["vant-auth", "vant-web", "vant-inventory", "vant-logs", "vant-aegis", "vant-bus"]
SERVICE_UNITS = [
    "vantsiem-auth",
    "vantsiem-web",
    "vantsiem-inventory",
    "vantsiem-logs",
    "vantsiem-aegis",
    "vantsiem-bus",
]

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"

# Directories/files to exclude from SFTP uploads
EXCLUDE_PATTERNS = [
    "__pycache__",
    "*.pyc",
    ".git",
    ".vscode",
    "node_modules",
    "*.egg-info",
    ".DS_Store",
    "db.sqlite3",
    "*.log",
]

# ─── Helpers ─────────────────────────────────────────────────────────────────

class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    END = "\033[0m"


def info(msg):
    print(f"{Colors.CYAN}[INFO]{Colors.END}  {msg}")


def ok(msg):
    print(f"{Colors.GREEN}[  OK]{Colors.END}  {msg}")


def warn(msg):
    print(f"{Colors.YELLOW}[WARN]{Colors.END}  {msg}")


def fail(msg):
    print(f"{Colors.RED}[FAIL]{Colors.END}  {msg}")


def step(n, total, msg):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}")
    print(f"  Step {n}/{total}: {msg}")
    print(f"{'='*60}{Colors.END}")


def sudo_cmd(cmd):
    """Wrap a command with sudo using password."""
    return f"echo '{DEFAULT_PASSWORD}' | sudo -S {cmd}"


def should_exclude(filename):
    """Check if a filename matches any exclusion pattern."""
    for pattern in EXCLUDE_PATTERNS:
        if fnmatch.fnmatch(filename, pattern):
            return True
    return False


# ─── SSH / SFTP Operations ──────────────────────────────────────────────────

class Deployer:
    def __init__(self, host, user, password):
        self.host = host
        self.user = user
        self.password = password
        self.client = paramiko.SSHClient()
        self.sftp = None

    def connect(self):
        info(f"Connecting to {self.user}@{self.host}...")
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            self.host,
            username=self.user,
            password=self.password,
            timeout=15,
            allow_agent=False,
            look_for_keys=False,
        )
        self.sftp = self.client.open_sftp()
        ok(f"Connected to {self.host}")

    def close(self):
        if self.sftp:
            self.sftp.close()
        self.client.close()

    def run(self, cmd, sudo=False, check=True, timeout=120):
        """Run a command on the remote server."""
        if sudo:
            cmd = sudo_cmd(cmd)
        info(f"  Exec: {cmd}")
        stdin, stdout, stderr = self.client.exec_command(cmd, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode(errors="replace").strip()
        err = stderr.read().decode(errors="replace").strip()
        # Remove sudo password prompt noise from stderr
        err_lines = [l for l in err.splitlines() if "[sudo]" not in l and "password" not in l.lower()]
        err_clean = "\n".join(err_lines).strip()
        if out:
            for line in out.splitlines():
                print(f"    {line}")
        if exit_code != 0 and check:
            fail(f"Command failed (exit {exit_code}): {cmd}")
            if err_clean:
                fail(f"  stderr: {err_clean}")
            raise RuntimeError(f"Remote command failed: {cmd}")
        if err_clean and exit_code == 0:
            warn(f"  stderr: {err_clean}")
        return out, err_clean, exit_code

    def mkdir_p(self, path):
        """Create remote directory recursively."""
        self.run(f"mkdir -p {path}", sudo=True, check=False)

    def upload_dir(self, local_dir, remote_dir, label=None):
        """Recursively upload a local directory via SFTP."""
        local_dir = Path(local_dir)
        label = label or local_dir.name
        uploaded = 0

        for root, dirs, files in os.walk(local_dir):
            # Filter out excluded directories
            dirs[:] = [d for d in dirs if not should_exclude(d)]

            rel = Path(root).relative_to(local_dir)
            remote_path = PurePosixPath(remote_dir) / rel

            self.mkdir_p(str(remote_path))

            for f in files:
                if should_exclude(f):
                    continue
                local_file = Path(root) / f
                remote_file = remote_path / f
                self.sftp.put(str(local_file), str(remote_file))
                uploaded += 1

        ok(f"Uploaded {label}: {uploaded} files")
        return uploaded

    def upload_file(self, local_file, remote_file):
        """Upload a single file."""
        self.sftp.put(str(local_file), str(remote_file))
        ok(f"Uploaded {local_file.name} -> {remote_file}")


# ─── Deployment Steps ────────────────────────────────────────────────────────

TOTAL_STEPS = 10


def step_01_create_dirs(d):
    step(1, TOTAL_STEPS, "Creating remote directory structure")
    dirs = [
        REMOTE_BASE,
        f"{REMOTE_BASE}/services",
        f"{REMOTE_BASE}/shared",
        LOG_DIR,
        "/etc/nginx/sites-enabled",
        "/etc/nginx/ssl",
    ]
    for svc in SERVICES:
        dirs.append(f"{REMOTE_BASE}/services/{svc}")
    for d_path in dirs:
        d.mkdir_p(d_path)
    ok("Directory structure created")


def step_02_upload_shared(d):
    step(2, TOTAL_STEPS, "Uploading shared library")
    d.upload_dir(PROJECT_ROOT / "shared", f"{REMOTE_BASE}/shared", "shared")


def step_03_upload_services(d):
    step(3, TOTAL_STEPS, "Uploading service directories")
    total = 0
    for svc in SERVICES:
        local = PROJECT_ROOT / svc
        if not local.exists():
            warn(f"Service directory not found: {local}, skipping")
            continue
        total += d.upload_dir(local, f"{REMOTE_BASE}/services/{svc}", svc)
    ok(f"Total files uploaded across all services: {total}")


def step_04_upload_env(d, skip_env=False):
    step(4, TOTAL_STEPS, "Uploading .env file")
    env_file = PROJECT_ROOT / ".env"
    env_template = PROJECT_ROOT / ".env.template"
    if skip_env:
        warn("Skipping .env upload (--skip-env)")
        return

    if env_file.exists():
        d.upload_file(env_file, f"{REMOTE_BASE}/.env")
    elif env_template.exists():
        warn("No .env found, uploading .env.template as .env")
        d.upload_file(env_template, f"{REMOTE_BASE}/.env")
    else:
        warn("No .env or .env.template found, skipping")
        return

    d.run(f"chmod 600 {REMOTE_BASE}/.env", sudo=True)
    ok(".env deployed")


def step_05_create_venv(d):
    step(5, TOTAL_STEPS, "Creating Python venv and installing dependencies")
    d.run(f"python3 -m venv {REMOTE_BASE}/venv", sudo=True)
    d.run(f"{REMOTE_BASE}/venv/bin/pip install --upgrade pip setuptools wheel", sudo=True)

    # Install shared library first
    shared_setup = f"{REMOTE_BASE}/shared/setup.py"
    d.run(f"test -f {shared_setup} && {REMOTE_BASE}/venv/bin/pip install {REMOTE_BASE}/shared/ || true", sudo=True)

    # Install requirements for each service
    for svc in SERVICES:
        req_file = f"{REMOTE_BASE}/services/{svc}/requirements.txt"
        d.run(f"test -f {req_file} && {REMOTE_BASE}/venv/bin/pip install -r {req_file} || true", sudo=True, timeout=300)

    ok("venv created and dependencies installed")


def step_06_ensure_db(d):
    step(6, TOTAL_STEPS, "Ensuring PostgreSQL and database exist")
    d.run("systemctl is-active postgresql || true", sudo=True, check=False)
    # Create database and user if they don't exist
    create_sql = (
        "DO $$ BEGIN "
        "IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'vantsiem') THEN "
        "CREATE ROLE vantsiem WITH LOGIN PASSWORD 'vantsiem'; "
        "END IF; END $$;"
    )
    d.run(f"psql -U postgres -c \"{create_sql}\"", sudo=True, check=False)
    d.run(
        "psql -U postgres -tc \"SELECT 1 FROM pg_database WHERE datname='vantsiem'\" | grep -q 1 || "
        "psql -U postgres -c 'CREATE DATABASE vantsiem OWNER vantsiem;'",
        sudo=True,
        check=False,
    )
    d.run("psql -U postgres -c \"GRANT ALL PRIVILEGES ON DATABASE vantsiem TO vantsiem;\"", sudo=True, check=False)
    ok("Database ready")


def step_07_migrate(d):
    step(7, TOTAL_STEPS, "Running migrations and creating superuser")
    migrate_services = ["vant-auth", "vant-inventory", "vant-logs", "vant-aegis", "vant-web"]
    for svc in migrate_services:
        svc_dir = f"{REMOTE_BASE}/services/{svc}"
        d.run(f"cd {svc_dir} && {REMOTE_BASE}/venv/bin/python manage.py migrate --noinput", sudo=True, timeout=180)

    # Create superuser
    shell_cmd = (
        "from auth_app.models import AuthUser; "
        "u, created = AuthUser.objects.get_or_create(username='admin', "
        "defaults={'email':'admin@vantsiem.local','role':'admin','first_name':'Admin','last_name':'System'}); "
        "u.set_password('admin'); u.save(); "
        "print('Superuser created' if created else 'Superuser already exists')"
    )
    d.run(
        f"cd {REMOTE_BASE}/services/vant-auth && "
        f"{REMOTE_BASE}/venv/bin/python manage.py shell -c \"{shell_cmd}\"",
        sudo=True,
        timeout=60,
    )
    ok("Migrations complete, superuser admin/admin ready")


def step_08_nginx(d, skip_nginx=False):
    step(8, TOTAL_STEPS, "Configuring nginx")
    if skip_nginx:
        warn("Skipping nginx configuration (--skip-nginx)")
        return

    nginx_conf = SCRIPTS_DIR / "nginx-vantsiem.conf"
    if nginx_conf.exists():
        d.upload_file(nginx_conf, "/tmp/vantsiem-nginx.conf")
        d.run("cp /tmp/vantsiem-nginx.conf /etc/nginx/sites-enabled/vantsiem", sudo=True)
        d.run("rm /tmp/vantsiem-nginx.conf", sudo=True)
    else:
        warn("nginx-vantsiem.conf not found, skipping")

    # Test and reload
    d.run("nginx -t", sudo=True, check=False)
    d.run("systemctl reload nginx", sudo=True, check=False)
    ok("Nginx configured")


def step_09_systemd(d):
    step(9, TOTAL_STEPS, "Installing and starting systemd services")
    service_files = [
        "vantsiem-auth.service",
        "vantsiem-web.service",
        "vantsiem-inventory.service",
        "vantsiem-logs.service",
        "vantsiem-aegis.service",
        "vantsiem-bus.service",
    ]

    for sf in service_files:
        local_path = SCRIPTS_DIR / sf
        if not local_path.exists():
            warn(f"Service file not found: {sf}, skipping")
            continue
        remote_path = f"/etc/systemd/system/{sf}"
        d.upload_file(local_path, remote_path)

    d.run("systemctl daemon-reload", sudo=True)

    for unit in SERVICE_UNITS:
        d.run(f"systemctl enable {unit}", sudo=True, check=False)
        d.run(f"systemctl restart {unit}", sudo=True, check=False)

    ok("All systemd services installed and started")


def step_10_status(d):
    step(10, TOTAL_STEPS, "Verifying deployment")
    time.sleep(3)  # Give services a moment to start

    print(f"\n{Colors.BOLD}{'='*60}")
    print(f"  Service Status")
    print(f"{'='*60}{Colors.END}")

    for unit in SERVICE_UNITS:
        out, _, code = d.run(f"systemctl is-active {unit}", sudo=True, check=False)
        status = out.strip() if out else "unknown"
        if status == "active":
            print(f"  {Colors.GREEN}✓{Colors.END} {unit}: {status}")
        else:
            print(f"  {Colors.RED}✗{Colors.END} {unit}: {status}")

    print(f"\n{Colors.BOLD}{'='*60}")
    print(f"  Endpoint Check")
    print(f"{'='*60}{Colors.END}")

    endpoints = [
        ("Auth", "http://127.0.0.1:8100/auth/"),
        ("Web", "http://127.0.0.1:8200/"),
        ("Inventory", "http://127.0.0.1:8300/inventory/api/"),
        ("Logs", "http://127.0.0.1:8400/logs/api/"),
        ("Aegis", "http://127.0.0.1:8500/aegis/api/"),
        ("Bus", "http://127.0.0.1:8600/api/alerts/"),
    ]
    for name, url in endpoints:
        out, _, code = d.run(f"curl -s -o /dev/null -w '%{{http_code}}' '{url}' || echo '000'", sudo=True, check=False)
        http_code = out.strip().strip("'")
        if http_code and http_code != "000" and http_code != "502":
            print(f"  {Colors.GREEN}✓{Colors.END} {name:12s} -> {url} [{http_code}]")
        else:
            print(f"  {Colors.YELLOW}~{Colors.END} {name:12s} -> {url} [{http_code}]")

    print(f"\n{Colors.BOLD}{'='*60}")
    print(f"  Deployment Complete!")
    print(f"  Server: {DEFAULT_SERVER}")
    print(f"  Login:  admin / admin")
    print(f"  Access: https://{DEFAULT_SERVER}/siem/")
    print(f"{'='*60}{Colors.END}\n")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="VANT-SIEM Deployment Script")
    parser.add_argument("--server", default=DEFAULT_SERVER, help=f"Server IP (default: {DEFAULT_SERVER})")
    parser.add_argument("--user", default=DEFAULT_USER, help=f"SSH user (default: {DEFAULT_USER})")
    parser.add_argument("--password", default=DEFAULT_PASSWORD, help="SSH password")
    parser.add_argument("--skip-env", action="store_true", help="Skip .env upload")
    parser.add_argument("--skip-nginx", action="store_true", help="Skip nginx configuration")
    parser.add_argument("--only", type=int, help="Run only a specific step number (1-10)")
    args = parser.parse_args()

    global DEFAULT_PASSWORD
    DEFAULT_PASSWORD = args.password

    print(f"""
{Colors.BOLD}{Colors.CYAN}
  ╔═══════════════════════════════════════════════╗
  ║         VANT-SIEM Deployment Script           ║
  ║         Microservices Platform                ║
  ╚═══════════════════════════════════════════════╝
{Colors.END}
  Server:   {args.server}
  User:     {args.user}
  Project:  {PROJECT_ROOT}
""")

    d = Deployer(args.server, args.user, args.password)

    try:
        d.connect()
    except Exception as e:
        fail(f"Could not connect: {e}")
        sys.exit(1)

    steps = {
        1: step_01_create_dirs,
        2: step_02_upload_shared,
        3: step_03_upload_services,
        4: lambda d_: step_04_upload_env(d_, args.skip_env),
        5: step_05_create_venv,
        6: step_06_ensure_db,
        7: step_07_migrate,
        8: lambda d_: step_08_nginx(d_, args.skip_nginx),
        9: step_09_systemd,
        10: step_10_status,
    }

    try:
        if args.only:
            if args.only not in steps:
                fail(f"Invalid step number: {args.only}. Valid: 1-{TOTAL_STEPS}")
                sys.exit(1)
            steps[args.only](d)
        else:
            for num, fn in steps.items():
                try:
                    fn(d)
                except RuntimeError as e:
                    fail(f"Step {num} failed: {e}")
                    warn("Continuing with remaining steps...")
    except KeyboardInterrupt:
        warn("\nDeployment interrupted by user")
    except Exception as e:
        fail(f"Unexpected error: {e}")
    finally:
        d.close()


if __name__ == "__main__":
    main()
