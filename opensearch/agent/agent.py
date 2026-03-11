import argparse
import socket
import sys
import time
from pathlib import Path

import yaml

from collectors.snort import SnortCollector
from collectors.suricata import SuricataCollector
from collectors.windows_eventlog import WindowsEventLogCollector
from collectors.postgres_log import PostgresLogCollector
from collectors.file_log import FileLogCollector
from output import OutputClient


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


def run(config_path):
    cfg = load_cfg(config_path)
    agent_cfg = cfg.get("agent", {})
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
                    },
                }
            )
        except Exception as exc:
            print(f"[agent] upsert_source failed for {c.source_type}: {exc}", file=sys.stderr)

    while True:
        batch = []
        for collector in collectors:
            try:
                events = collector.collect()
                for ev in events:
                    _ensure_host_fields(ev, agent_cfg.get("host_name", ""), agent_cfg.get("host_ip", ""))
                batch.extend(events)
            except Exception as exc:
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
        except Exception as exc:
            # Keep agent running even if output endpoint is down.
            print(f"[agent] send_events failed: {exc}", file=sys.stderr)
        time.sleep(interval)


def default_config_path():
    # If running as bundled .exe, use config.yaml in executable directory.
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).resolve().parent / "config.yaml")
    return "opensearch/agent/config.yaml"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=default_config_path())
    args = parser.parse_args()
    run(args.config)
