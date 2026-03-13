import ctypes
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate():
    params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
    rc = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, None, 1
    )
    return rc > 32


def main():
    if not is_admin():
        if not elevate():
            print("Administrator privileges are required.")
            return 1
        return 0

    base_dir = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    package_zip = base_dir / "package.zip"
    if not package_zip.exists():
        print(f"package.zip not found: {package_zip}")
        return 1

    workdir = Path(tempfile.gettempdir()) / "vant_opensearch_agent_setup"
    if workdir.exists():
        for item in workdir.glob("*"):
            if item.is_file():
                item.unlink(missing_ok=True)
    workdir.mkdir(parents=True, exist_ok=True)

    extract_dir = workdir / "package"
    if extract_dir.exists():
        for item in extract_dir.rglob("*"):
            if item.is_file():
                item.unlink(missing_ok=True)
    extract_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(package_zip, "r") as zf:
        zf.extractall(extract_dir)

    install_script = extract_dir / "Install-OpenSearchAgent.ps1"
    if not install_script.exists():
        print(f"Install script not found: {install_script}")
        return 1

    cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(install_script),
        "-RunNow",
    ]
    result = subprocess.run(cmd, cwd=str(extract_dir), check=False)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
