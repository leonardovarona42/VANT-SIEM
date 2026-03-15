import argparse
import logging
import socket
import sys
import time
import os
import threading
import json
import subprocess
import platform
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

import yaml
import requests

from collectors.snort import SnortCollector
from collectors.suricata import SuricataCollector
from collectors.windows_eventlog import WindowsEventLogCollector
from collectors.postgres_log import PostgresLogCollector
from collectors.file_log import FileLogCollector
from output import OutputClient

AGENT_VERSION = "v1.01"


def load_cfg(path):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


def build_collectors(cfg):
    agent_cfg = cfg.get("agent", {})
    collectors_cfg = cfg.get("collectors", {})
    collectors = []

    if collectors_cfg.get("snort", {}).get("enabled"):
        collectors.append(SnortCollector(collectors_cfg.get("snort"), agent_cfg))
    if collectors_cfg.get("suricata", {}).get("enabled"):
        collectors.append(SuricataCollector(collectors_cfg.get("suricata"), agent_cfg))
    if collectors_cfg.get("windows_eventlog", {}).get("enabled"):
        collectors.append(WindowsEventLogCollector(collectors_cfg.get("windows_eventlog"), agent_cfg))
    if collectors_cfg.get("postgres", {}).get("enabled"):
        collectors.append(PostgresLogCollector(collectors_cfg.get("postgres"), agent_cfg))
    if collectors_cfg.get("file_logs", {}).get("enabled"):
        collectors.append(FileLogCollector(collectors_cfg.get("file_logs"), agent_cfg))

    return collectors


def _detect_host():
    hostname = socket.gethostname()
    ip = ""
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        ip = ""
    if ip.startswith("127.") or not ip:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
        except Exception:
            ip = ""
    return hostname, ip


def _ensure_host_fields(event, host_name, host_ip):
    if not event.get("host_name"):
        event["host_name"] = host_name
    raw = event.get("raw_payload")
    if raw is None or not isinstance(raw, dict):
        raw = {}
    if host_name and "host_name" not in raw:
        raw["host_name"] = host_name
    if host_ip and "host_ip" not in raw:
        raw["host_ip"] = host_ip
    event["raw_payload"] = raw
    return event


def _configure_logging(agent_cfg):
    level_name = str(agent_cfg.get("log_level", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)
    log_file = agent_cfg.get("log_file")
    if not log_file:
        # Default to /var/log on Linux, executable dir otherwise.
        if sys.platform.startswith("linux"):
            log_file = "/var/log/vant-siem/agent.log"
        else:
            log_file = str(Path(sys.executable).resolve().parent / "agent.log")

    log_dir = Path(log_file).parent
    log_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("vant-siem-agent")
    logger.setLevel(level)

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # File handler with rotation
    max_bytes = int(agent_cfg.get("log_max_bytes", 10 * 1024 * 1024))
    backup_count = int(agent_cfg.get("log_backup_count", 5))
    file_handler = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
    file_handler.setFormatter(fmt)
    file_handler.setLevel(level)
    logger.addHandler(file_handler)

    # Also log to stdout for systemd/journald
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(fmt)
    stream_handler.setLevel(level)
    logger.addHandler(stream_handler)

    return logger


def _sleep_with_stop(stop_event, seconds):
    remaining = max(0, int(seconds))
    while remaining > 0:
        if stop_event.is_set():
            return
        time.sleep(1)
        remaining -= 1


def _control_config(cfg):
    return cfg.get("control", {}) or {}


def _control_headers(token):
    return {"Authorization": f"Bearer {token}"} if token else {}


def _control_post(url, payload, token, timeout=8):
    headers = _control_headers(token)
    return requests.post(url, json=payload, headers=headers, timeout=timeout)


def _collect_inventory():
    info = {
        "host": socket.gethostname(),
        "os": platform.platform(),
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }

    def run_cmd(cmd):
        try:
            out = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)
            return out.strip()
        except Exception:
            return ""

    info["bios_serial"] = run_cmd("wmic bios get serialnumber")
    info["csproduct"] = run_cmd("wmic csproduct get name,uuid")
    info["cpu"] = run_cmd("wmic cpu get name,ProcessorId")
    info["baseboard"] = run_cmd("wmic baseboard get product,serialnumber,manufacturer")
    info["os_details"] = run_cmd("wmic os get Caption,Version,BuildNumber,SerialNumber,InstallDate,LastBootUpTime")
    info["logged_users"] = run_cmd("query user")

    # Installed apps (best-effort, can be slow on some systems)
    info["installed_apps"] = run_cmd(
        'powershell -NoProfile -Command "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* '
        '| Select-Object DisplayName,DisplayVersion,Publisher '
        '| ConvertTo-Json -Compress"'
    )
    return info


def _current_ips():
    ips = set()
    try:
        hostname = socket.gethostname()
        ips.add(socket.gethostbyname(hostname))
    except Exception:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ips.add(s.getsockname()[0])
    except Exception:
        pass
    return [ip for ip in ips if ip and not ip.startswith("127.")]


def run_with_stop(config_path, stop_event):
    cfg = load_cfg(config_path)
    agent_cfg = cfg.get("agent", {})
    logger = _configure_logging(agent_cfg)
    host_name, host_ip = _detect_host()
    placeholder_hosts = {
        "debian-host",
        "ubuntu-host",
        "windows-host-01",
        "windows-server-ad",
        "windows11-ids",
        "zentyal-ad",
    }
    configured_host = (agent_cfg.get("host_name") or "").strip()
    if (not configured_host) or (configured_host.lower() in placeholder_hosts):
        agent_cfg["host_name"] = host_name
    if host_ip and not agent_cfg.get("host_ip"):
        agent_cfg["host_ip"] = host_ip
    out = OutputClient(cfg.get("output", {}))
    collectors = build_collectors(cfg)
    interval = int(agent_cfg.get("interval_seconds", 10))
    log_every = int(agent_cfg.get("log_every_cycles", 60))
    control_cfg = _control_config(cfg)
    control_server = (control_cfg.get("server_url") or "").rstrip("/")
    control_poll = int(control_cfg.get("poll_seconds", 30))
    control_token = (
        cfg.get("output", {}).get("auth", {}).get("token")
        or control_cfg.get("token", "")
    )
    next_control = time.time() + control_poll
    next_inventory = time.time() + int(control_cfg.get("inventory_seconds", 86400))
    cycle = 0

    logger.info(
        "agent.starting version=%s host=%s ip=%s interval=%ss collectors=%s",
        AGENT_VERSION,
        agent_cfg.get("host_name", ""),
        agent_cfg.get("host_ip", ""),
        interval,
        ",".join([c.source_type for c in collectors]) or "none",
    )

    # register/upsert enabled sources
    for c in collectors:
        try:
            out.upsert_source(
                {
                    "source_id": f"{agent_cfg.get('id','agent')}-{c.source_type}",
                    "source_type": c.source_type,
                    "host_name": agent_cfg.get("host_name", ""),
                    "enabled": True,
                    "meta": {
                        **(c.cfg or {}),
                        "host_name": agent_cfg.get("host_name", ""),
                        "host_ip": agent_cfg.get("host_ip", ""),
                        "agent_version": AGENT_VERSION,
                    },
                }
            )
        except Exception as exc:
            logger.warning("upsert_source failed source=%s error=%s", c.source_type, exc)

    while not stop_event.is_set():
        try:
            cycle += 1
            batch = []
            for collector in collectors:
                try:
                    events = collector.collect()
                    for ev in events:
                        _ensure_host_fields(ev, agent_cfg.get("host_name", ""), agent_cfg.get("host_ip", ""))
                    batch.extend(events)
                except Exception as exc:
                    logger.exception("collector failed source=%s", collector.source_type)
                    batch.append(
                        _ensure_host_fields(
                            {
                            "source_type": "agent",
                            "source_name": "agent-runtime",
                            "host_name": agent_cfg.get("host_name", ""),
                            "event_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "severity": "error",
                            "event_category": "agent.error",
                            "message": f"collector {collector.source_type} failed: {exc}",
                            "raw_payload": {},
                            "tags": ["agent", "error"],
                            },
                            agent_cfg.get("host_name", ""),
                            agent_cfg.get("host_ip", ""),
                        )
                    )
            try:
                out.send_events(batch)
                if log_every > 0 and (cycle % log_every == 0):
                    logger.info("cycle ok events=%s collectors=%s", len(batch), len(collectors))
            except Exception as exc:
                # Keep agent running even if output endpoint is down.
                logger.error("send_events failed error=%s batch=%s", exc, len(batch))
            now = time.time()
            if control_server and now >= next_control:
                try:
                    payload = {
                        "agent_id": agent_cfg.get("id", "agent"),
                        "host_name": agent_cfg.get("host_name", ""),
                        "host_ip": agent_cfg.get("host_ip", ""),
                        "agent_version": AGENT_VERSION,
                        "ips": _current_ips(),
                    }
                    _control_post(
                        f"{control_server}/api/agent/heartbeat/",
                        payload,
                        control_token,
                        timeout=8,
                    )
                    cmd_resp = _control_post(
                        f"{control_server}/api/agent/commands/pull/",
                        {"agent_id": agent_cfg.get("id", "agent")},
                        control_token,
                        timeout=8,
                    )
                    if cmd_resp.status_code == 200:
                        data = cmd_resp.json()
                        command = data.get("command")
                        command_id = data.get("command_id")
                        if command == "stop":
                            logger.warning("command.stop received")
                            stop_event.set()
                        elif command == "restart":
                            logger.warning("command.restart received")
                            os._exit(3)
                        elif command == "activate":
                            logger.info("command.activate received")
                        if command_id:
                            _control_post(
                                f"{control_server}/api/agent/commands/ack/",
                                {"command_id": command_id, "status": "done"},
                                control_token,
                                timeout=8,
                            )
                except Exception as exc:
                    logger.warning("control poll failed error=%s", exc)
                next_control = now + control_poll

            if control_server and now >= next_inventory:
                try:
                    inv = _collect_inventory()
                    _control_post(
                        f"{control_server}/api/agent/inventory/",
                        {"agent_id": agent_cfg.get("id", "agent"), "inventory": inv},
                        control_token,
                        timeout=12,
                    )
                except Exception as exc:
                    logger.warning("inventory upload failed error=%s", exc)
                next_inventory = now + int(control_cfg.get("inventory_seconds", 86400))

            _sleep_with_stop(stop_event, interval)
        except Exception as exc:
            logger.exception("agent.loop crashed error=%s", exc)
            _sleep_with_stop(stop_event, 5)


def run(config_path):
    class _Stop:
        def is_set(self):
            return False

    run_with_stop(config_path, _Stop())


def default_config_path():
    # If running as bundled .exe, use config.yaml in executable directory.
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).resolve().parent / "config.yaml")
    return "opensearch_agents/config.yaml"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=default_config_path())
    args = parser.parse_args()
    run(args.config)
