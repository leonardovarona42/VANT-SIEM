import hashlib
import json
import os
import platform
import re
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def _safe_json_command(command):
    try:
        out = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.DEVNULL)
        out = out.strip()
        if not out:
            return []
        data = json.loads(out)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        return []
    except Exception:
        return []


def _safe_text_command(command):
    try:
        return subprocess.check_output(command, shell=True, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""


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


def _normalize_apps(items):
    apps = []
    for item in items:
        name = item.get("DisplayName") or item.get("Name") or item.get("name") or ""
        if not name:
            continue
        version = item.get("DisplayVersion") or item.get("Version") or item.get("version") or ""
        publisher = item.get("Publisher") or item.get("Vendor") or item.get("publisher") or ""
        apps.append(
            {
                "name": name,
                "version": version,
                "publisher": publisher,
                "fingerprint": f"{name}|{version}|{publisher}".lower()[:255],
            }
        )
    return apps


def _parse_logged_users(raw_text):
    users = []
    for line in raw_text.splitlines():
        if not line.strip() or line.lower().startswith("username"):
            continue
        parts = [p for p in re.split(r"\s{2,}", line.strip()) if p]
        if parts:
            users.append({"username": parts[0], "raw": line.strip()})
    return users


def _collect_windows_inventory():
    hostname = socket.gethostname()
    inventory = {
        "host": hostname,
        "os": platform.platform(),
        "collected_at": _utc_now(),
        "hardware": [],
        "software": [],
        "network": [],
        "users": [],
        "usb_devices": [],
        "raw": {},
    }

    bios = _safe_json_command(
        'powershell -NoProfile -Command "Get-CimInstance Win32_BIOS | Select-Object SerialNumber,Manufacturer,SMBIOSBIOSVersion | ConvertTo-Json -Compress"'
    )
    for item in bios:
        inventory["hardware"].append(
            {
                "component_type": "bios",
                "name": "BIOS",
                "vendor": item.get("Manufacturer", ""),
                "model": item.get("SMBIOSBIOSVersion", ""),
                "serial_number": item.get("SerialNumber", ""),
                "fingerprint": f"bios|{item.get('SerialNumber', '')}",
            }
        )

    systems = _safe_json_command(
        'powershell -NoProfile -Command "Get-CimInstance Win32_ComputerSystemProduct | Select-Object Name,Vendor,UUID,IdentifyingNumber | ConvertTo-Json -Compress"'
    )
    for item in systems:
        inventory["hardware"].append(
            {
                "component_type": "system",
                "name": item.get("Name", "System"),
                "vendor": item.get("Vendor", ""),
                "model": item.get("UUID", ""),
                "serial_number": item.get("IdentifyingNumber", ""),
                "fingerprint": f"system|{item.get('UUID', '')}|{item.get('IdentifyingNumber', '')}",
            }
        )

    cpus = _safe_json_command(
        'powershell -NoProfile -Command "Get-CimInstance Win32_Processor | Select-Object Name,Manufacturer,ProcessorId | ConvertTo-Json -Compress"'
    )
    for item in cpus:
        inventory["hardware"].append(
            {
                "component_type": "cpu",
                "name": item.get("Name", ""),
                "vendor": item.get("Manufacturer", ""),
                "model": "",
                "serial_number": item.get("ProcessorId", ""),
                "fingerprint": f"cpu|{item.get('ProcessorId', '')}|{item.get('Name', '')}",
            }
        )

    boards = _safe_json_command(
        'powershell -NoProfile -Command "Get-CimInstance Win32_BaseBoard | Select-Object Product,Manufacturer,SerialNumber | ConvertTo-Json -Compress"'
    )
    for item in boards:
        inventory["hardware"].append(
            {
                "component_type": "board",
                "name": item.get("Product", "BaseBoard"),
                "vendor": item.get("Manufacturer", ""),
                "model": item.get("Product", ""),
                "serial_number": item.get("SerialNumber", ""),
                "fingerprint": f"board|{item.get('SerialNumber', '')}|{item.get('Product', '')}",
            }
        )

    disks = _safe_json_command(
        'powershell -NoProfile -Command "Get-CimInstance Win32_DiskDrive | Select-Object Model,Manufacturer,SerialNumber,Size,InterfaceType,MediaType | ConvertTo-Json -Compress"'
    )
    for item in disks:
        inventory["hardware"].append(
            {
                "component_type": "disk",
                "name": item.get("Model", "Disk"),
                "vendor": item.get("Manufacturer", ""),
                "model": item.get("Model", ""),
                "serial_number": item.get("SerialNumber", ""),
                "fingerprint": f"disk|{item.get('SerialNumber', '')}|{item.get('Model', '')}",
                "metadata": {
                    "size": item.get("Size"),
                    "interface": item.get("InterfaceType"),
                    "media_type": item.get("MediaType"),
                },
            }
        )

    adapters = _safe_json_command(
        'powershell -NoProfile -Command "Get-NetAdapter | Select-Object Name,InterfaceDescription,MacAddress,Status,LinkSpeed | ConvertTo-Json -Compress"'
    )
    addresses = _safe_json_command(
        'powershell -NoProfile -Command "Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,IPAddress,PrefixLength | ConvertTo-Json -Compress"'
    )
    for adapter in adapters:
        mac = adapter.get("MacAddress", "")
        iface = adapter.get("Name", "")
        if mac:
            inventory["network"].append(
                {
                    "address_type": "mac",
                    "address": mac,
                    "mac_address": mac,
                    "interface_name": iface,
                    "fingerprint": f"mac|{iface}|{mac}",
                    "status": adapter.get("Status", ""),
                    "link_speed": adapter.get("LinkSpeed", ""),
                }
            )
            inventory["hardware"].append(
                {
                    "component_type": "network",
                    "name": iface,
                    "vendor": "",
                    "model": adapter.get("InterfaceDescription", ""),
                    "serial_number": mac,
                    "fingerprint": f"nic|{iface}|{mac}",
                    "metadata": adapter,
                }
            )
    for item in addresses:
        ip = item.get("IPAddress", "")
        iface = item.get("InterfaceAlias", "")
        if ip:
            inventory["network"].append(
                {
                    "address_type": "ipv4",
                    "address": ip,
                    "interface_name": iface,
                    "fingerprint": f"ipv4|{iface}|{ip}",
                    "prefix_length": item.get("PrefixLength"),
                }
            )

    apps = _safe_json_command(
        'powershell -NoProfile -Command "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | ConvertTo-Json -Compress"'
    )
    inventory["software"] = _normalize_apps(apps)

    usb = _safe_json_command(
        'powershell -NoProfile -Command "Get-PnpDevice -Class USB | Select-Object FriendlyName,InstanceId,Status,Class,Manufacturer | ConvertTo-Json -Compress"'
    )
    for item in usb:
        inventory["usb_devices"].append(
            {
                "name": item.get("FriendlyName", ""),
                "device_id": item.get("InstanceId", ""),
                "status": item.get("Status", ""),
                "vendor": item.get("Manufacturer", ""),
                "fingerprint": f"usb|{item.get('InstanceId', '')}",
            }
        )
        inventory["hardware"].append(
            {
                "component_type": "usb",
                "name": item.get("FriendlyName", ""),
                "vendor": item.get("Manufacturer", ""),
                "model": item.get("Class", ""),
                "serial_number": item.get("InstanceId", ""),
                "fingerprint": f"usb|{item.get('InstanceId', '')}",
                "status": item.get("Status", ""),
            }
        )

    logged_users = _safe_text_command("query user")
    inventory["raw"]["logged_users"] = logged_users
    inventory["users"] = _parse_logged_users(logged_users)
    return inventory


class AuditInventoryService:
    service_name = "asset_audit"

    def __init__(self, config_path):
        self.config_path = config_path
        self.state_path = _state_dir(config_path) / "audit_inventory_state.json"
        self.state = _load_state(self.state_path)

    def collect(self):
        inventory = _collect_windows_inventory() if os.name == "nt" else {
            "host": socket.gethostname(),
            "os": platform.platform(),
            "collected_at": _utc_now(),
            "hardware": [],
            "software": [],
            "network": [],
            "users": [],
            "usb_devices": [],
            "raw": {},
        }

        events = self._build_timeline_events(inventory)
        inventory["timeline_events"] = events
        self.state = {
            "software": sorted([item["fingerprint"] for item in inventory.get("software", [])]),
            "network": sorted([item["fingerprint"] for item in inventory.get("network", []) if item.get("fingerprint")]),
            "usb": sorted([item["fingerprint"] for item in inventory.get("usb_devices", []) if item.get("fingerprint")]),
            "users": sorted([item["username"] for item in inventory.get("users", []) if item.get("username")]),
        }
        _save_state(self.state_path, self.state)
        return inventory

    def _build_timeline_events(self, inventory):
        now = _utc_now()
        previous = self.state or {}
        events = []

        previous_software = set(previous.get("software", []))
        current_software = {item["fingerprint"]: item for item in inventory.get("software", []) if item.get("fingerprint")}
        for fingerprint, item in current_software.items():
            if fingerprint not in previous_software:
                events.append(
                    {
                        "category": "software",
                        "event_type": "software_observed",
                        "title": f"Software detectado: {item.get('name', '')}",
                        "description": f"Version {item.get('version', '')} publisher {item.get('publisher', '')}",
                        "severity": "info",
                        "observed_at": now,
                        "source_service": self.service_name,
                        "metadata": item,
                    }
                )

        previous_network = set(previous.get("network", []))
        current_network = {item["fingerprint"]: item for item in inventory.get("network", []) if item.get("fingerprint")}
        for fingerprint, item in current_network.items():
            if fingerprint not in previous_network:
                events.append(
                    {
                        "category": "network",
                        "event_type": "network_identity_observed",
                        "title": f"Red detectada: {item.get('address', '')}",
                        "description": item.get("interface_name", ""),
                        "severity": "info",
                        "observed_at": now,
                        "source_service": self.service_name,
                        "metadata": item,
                    }
                )

        previous_usb = set(previous.get("usb", []))
        current_usb = {item["fingerprint"]: item for item in inventory.get("usb_devices", []) if item.get("fingerprint")}
        for fingerprint, item in current_usb.items():
            if fingerprint not in previous_usb:
                events.append(
                    {
                        "category": "usb",
                        "event_type": "usb_device_observed",
                        "title": f"USB detectado: {item.get('name', '')}",
                        "description": item.get("device_id", ""),
                        "severity": "medium",
                        "observed_at": now,
                        "source_service": self.service_name,
                        "metadata": item,
                    }
                )

        previous_users = set(previous.get("users", []))
        current_users = {item["username"]: item for item in inventory.get("users", []) if item.get("username")}
        for username, item in current_users.items():
            if username not in previous_users:
                events.append(
                    {
                        "category": "user",
                        "event_type": "user_session_observed",
                        "title": f"Usuario detectado: {username}",
                        "description": item.get("raw", ""),
                        "severity": "info",
                        "actor": username,
                        "observed_at": now,
                        "source_service": self.service_name,
                        "metadata": item,
                    }
                )

        return events
