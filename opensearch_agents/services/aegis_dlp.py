import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZipFile

import requests


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def _state_dir(config_path):
    base = Path(config_path).resolve().parent
    state_dir = base / ".agent_state"
    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir


def _load_state(path):
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_state(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _expand_scan_paths(paths):
    expanded = []
    seen = set()
    for path in paths or []:
        value = os.path.expandvars(os.path.expanduser(path))
        if not value:
            continue
        resolved = str(Path(value))
        key = resolved.lower()
        if key in seen:
            continue
        seen.add(key)
        expanded.append(Path(resolved))
    return expanded


def _default_paths():
    paths = []
    system_drive = os.environ.get("SystemDrive", "C:").rstrip("\\/")
    users_root = Path(f"{system_drive}\\") / "Users"
    public_root = users_root / "Public"
    for root in (public_root,):
        paths.extend(
            [
                root / "Desktop",
                root / "Documents",
                root / "Downloads",
            ]
        )

    if users_root.exists():
        for profile in users_root.iterdir():
            if not profile.is_dir():
                continue
            if profile.name.lower() in {"all users", "default", "default user", "public"}:
                continue
            paths.extend(
                [
                    profile / "Desktop",
                    profile / "Documents",
                    profile / "Downloads",
                ]
            )

    program_data = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
    paths.extend(
        [
            program_data / "VANT" / "Drops",
            Path(os.environ.get("TEMP", r"C:\Temp")),
        ]
    )
    return _expand_scan_paths([str(path) for path in paths])


def _iter_files(paths, extensions, max_file_size):
    seen = set()
    for base in paths:
        if not base.exists():
            continue
        for root, _, files in os.walk(base):
            for name in files:
                path = Path(root) / name
                if str(path) in seen:
                    continue
                seen.add(str(path))
                if extensions and path.suffix.lower() not in extensions:
                    continue
                try:
                    if path.stat().st_size > max_file_size:
                        continue
                except Exception:
                    continue
                yield path


def _read_file_text(path):
    suffix = path.suffix.lower()
    try:
        if suffix in {".docx", ".xlsx", ".pptx"}:
            text_parts = []
            with ZipFile(path, "r") as zf:
                for member in zf.namelist():
                    if member.endswith(".xml"):
                        try:
                            text_parts.append(zf.read(member).decode("utf-8", errors="ignore"))
                        except Exception:
                            continue
            return "\n".join(text_parts)
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        try:
            return path.read_bytes().decode("utf-8", errors="ignore")
        except Exception:
            return ""


def _sha256(path):
    try:
        h = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _file_owner(path):
    if os.name != "nt":
        return ""
    command = (
        'powershell -NoProfile -Command '
        f'"(Get-Acl -LiteralPath \'{str(path).replace("\'","\'\'")}\').Owner"'
    )
    try:
        return subprocess.check_output(command, shell=True, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""


def _path_channel(path):
    low = str(path).lower()
    if "\\downloads\\" in low:
        return "downloads"
    if "\\desktop\\" in low:
        return "desktop"
    if "\\documents\\" in low:
        return "documents"
    return "filesystem"


def _metadata_haystack(path, content):
    stat = path.stat() if path.exists() else None
    values = [
        path.name,
        str(path),
        path.suffix.lower(),
        _file_owner(path),
        content,
    ]
    if stat is not None:
        values.extend(
            [
                str(stat.st_size),
                datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
                datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            ]
        )
    return "\n".join([item for item in values if item]).lower()


class AegisDlpService:
    module_name = "aegis_dlp"

    def __init__(self, config_path, cfg):
        self.config_path = config_path
        self.cfg = cfg or {}
        self.state_path = _state_dir(config_path) / "aegis_dlp_state.json"
        self.state = _load_state(self.state_path)
        self.remote_config = {}

    def fetch_remote_config(self, control_server, token, agent_id):
        if not control_server:
            return self.remote_config
        try:
            response = requests.post(
                f"{control_server}/api/agent/dlp/config/",
                json={"agent_id": agent_id},
                headers={"Authorization": f"Bearer {token}"} if token else {},
                timeout=10,
            )
            if response.status_code == 200:
                data = response.json()
                self.remote_config = data.get("config") or {}
        except Exception:
            return self.remote_config
        return self.remote_config

    def scan(self):
        dlp_cfg = self.cfg.get(self.module_name, {}) or {}
        if not dlp_cfg.get("enabled", True):
            return []

        policies = (self.remote_config or {}).get("policies") or []
        if not policies:
            return []

        rules = []
        scan_paths = []
        monitored_extensions = set()
        max_file_size_mb = int(dlp_cfg.get("max_file_size_mb", 10) or 10)
        for policy in policies:
            scan_paths.extend(policy.get("scan_paths") or [])
            monitored_extensions.update([ext.lower() for ext in (policy.get("monitored_extensions") or [])])
            max_file_size_mb = max(max_file_size_mb, int(policy.get("max_file_size_mb", 10) or 10))
            for rule in policy.get("rules") or []:
                rules.append((policy, rule))

        if not scan_paths:
            scan_paths = [str(path) for path in _default_paths()]

        scan_paths.extend(dlp_cfg.get("scan_paths") or [])
        monitored_extensions.update([ext.lower() for ext in (dlp_cfg.get("monitored_extensions") or [])])
        paths = _expand_scan_paths(scan_paths)
        max_file_size = max_file_size_mb * 1024 * 1024

        incidents = []
        known = set(self.state.get("incident_keys", []))
        for path in _iter_files(paths, monitored_extensions, max_file_size):
            content = _read_file_text(path)
            haystack = _metadata_haystack(path, content)
            if not haystack.strip():
                continue
            for policy, rule in rules:
                pattern = (rule.get("pattern") or "").strip()
                if not pattern:
                    continue
                matched_terms = []
                match_type = (rule.get("match_type") or "keyword").strip().lower()
                if match_type == "regex":
                    if re.search(pattern, haystack, flags=re.IGNORECASE):
                        matched_terms.append(pattern)
                elif match_type == "metadata":
                    if pattern.lower() in haystack:
                        matched_terms.append(pattern)
                else:
                    if pattern.lower() in haystack:
                        matched_terms.append(pattern)
                if not matched_terms:
                    continue

                file_hash = _sha256(path)
                incident_key = hashlib.sha256(
                    f"{file_hash}|{path}|{policy.get('code')}|{rule.get('name')}".encode("utf-8")
                ).hexdigest()
                if incident_key in known:
                    continue
                known.add(incident_key)
                incidents.append(
                    {
                        "fingerprint": incident_key,
                        "policy_code": policy.get("code", ""),
                        "rule_name": rule.get("name", ""),
                        "classification": rule.get("classification") or policy.get("code", ""),
                        "severity": rule.get("severity") or policy.get("severity", "high"),
                        "file_name": path.name,
                        "file_path": str(path),
                        "file_hash": file_hash,
                        "actor": _file_owner(path),
                        "channel": _path_channel(path),
                        "status": "open",
                        "detected_at": _utc_now(),
                        "summary": f"Coincidencia DLP en {path.name}",
                        "matched_keywords": matched_terms,
                        "metadata": {
                            "size": path.stat().st_size if path.exists() else 0,
                            "suffix": path.suffix.lower(),
                            "created_at": datetime.fromtimestamp(path.stat().st_ctime, tz=timezone.utc).isoformat() if path.exists() else "",
                            "modified_at": datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat() if path.exists() else "",
                        },
                    }
                )
        self.state["incident_keys"] = sorted(list(known))[-5000:]
        _save_state(self.state_path, self.state)
        return incidents
