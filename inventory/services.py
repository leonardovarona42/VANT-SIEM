import json
import hashlib
import re
from datetime import datetime, timezone as datetime_timezone

from django.utils import timezone
from django.utils.dateparse import parse_datetime

from .models import (
    AegisDlpIncident,
    AegisDlpPolicy,
    AegisDlpRule,
    AgentDevice,
    AgentHardwareComponent,
    AgentInventorySnapshot,
    AgentNetworkIdentity,
    AgentSoftwareRecord,
    AgentTimelineEvent,
)


DEFAULT_AEGIS_POLICY = {
    "name": "Aegis Sovereign Shield",
    "code": "aegis-sovereign-shield",
    "description": "Reglas base para proteger informacion clasificada y sensible.",
    "severity": "critical",
    "scan_paths": [],
    "monitored_extensions": [
        ".txt",
        ".log",
        ".csv",
        ".json",
        ".xml",
        ".md",
        ".docx",
        ".xlsx",
        ".pptx",
        ".pdf",
    ],
    "rules": [
        {
            "name": "Clasificado",
            "classification": "clasificado",
            "severity": "critical",
            "match_type": "keyword",
            "pattern": "informacion clasificada",
            "tags": ["estado", "clasificado"],
        },
        {
            "name": "Secreto",
            "classification": "secreto",
            "severity": "critical",
            "match_type": "keyword",
            "pattern": "secreto",
            "tags": ["estado", "secreto"],
        },
        {
            "name": "Seguridad del Estado",
            "classification": "seguridad_del_estado",
            "severity": "critical",
            "match_type": "keyword",
            "pattern": "seguridad del estado",
            "tags": ["estado", "seguridad"],
        },
        {
            "name": "Restringido",
            "classification": "restringido",
            "severity": "high",
            "match_type": "keyword",
            "pattern": "restringido",
            "tags": ["restringido"],
        },
    ],
}


def ensure_default_aegis_policy():
    policy, _ = AegisDlpPolicy.objects.get_or_create(
        code=DEFAULT_AEGIS_POLICY["code"],
        defaults={
            "name": DEFAULT_AEGIS_POLICY["name"],
            "description": DEFAULT_AEGIS_POLICY["description"],
            "enabled": True,
            "severity": DEFAULT_AEGIS_POLICY["severity"],
            "scan_paths": DEFAULT_AEGIS_POLICY["scan_paths"],
            "monitored_extensions": DEFAULT_AEGIS_POLICY["monitored_extensions"],
        },
    )
    for item in DEFAULT_AEGIS_POLICY["rules"]:
        AegisDlpRule.objects.get_or_create(
            policy=policy,
            name=item["name"],
            defaults={
                "enabled": True,
                "classification": item["classification"],
                "severity": item["severity"],
                "match_type": item["match_type"],
                "pattern": item["pattern"],
                "tags": item["tags"],
            },
        )
    return policy


def _parse_dt(value):
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str) and value:
        dt = parse_datetime(value)
    else:
        dt = None
    if dt is None:
        return timezone.now()
    if timezone.is_naive(dt):
        return timezone.make_aware(dt, datetime_timezone.utc)
    return dt


def _software_from_payload(payload):
    software = payload.get("software")
    if isinstance(software, list):
        return software
    raw = payload.get("installed_apps")
    if isinstance(raw, list):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            data = json.loads(raw)
            return data if isinstance(data, list) else []
        except Exception:
            return []
    return []


def _fingerprint(*parts):
    values = [str(part).strip().lower() for part in parts if str(part).strip()]
    return "|".join(values)[:255]


def _upsert_hardware(agent, items):
    active = set()
    for item in items or []:
        component_type = (item.get("component_type") or item.get("type") or "other").strip().lower()
        fingerprint = _fingerprint(
            item.get("fingerprint"),
            item.get("serial_number"),
            item.get("serial"),
            item.get("device_id"),
            item.get("name"),
            item.get("model"),
        )
        if not fingerprint:
            continue
        active.add((component_type, fingerprint))
        obj, _ = AgentHardwareComponent.objects.get_or_create(
            agent=agent,
            component_type=component_type,
            fingerprint=fingerprint,
            defaults={
                "name": item.get("name", ""),
                "vendor": item.get("vendor", ""),
                "model": item.get("model", ""),
                "serial_number": item.get("serial_number") or item.get("serial", ""),
                "status": "active",
                "metadata": item,
            },
        )
        obj.name = item.get("name", obj.name)
        obj.vendor = item.get("vendor", obj.vendor)
        obj.model = item.get("model", obj.model)
        obj.serial_number = item.get("serial_number") or item.get("serial", obj.serial_number)
        obj.status = item.get("status", "active")
        obj.metadata = item
        obj.save()

    for component in AgentHardwareComponent.objects.filter(agent=agent):
        if (component.component_type, component.fingerprint) not in active:
            if component.status != "inactive":
                component.status = "inactive"
                component.save(update_fields=["status", "last_seen"])


def _upsert_software(agent, items):
    active = set()
    for item in items or []:
        name = item.get("DisplayName") or item.get("name") or ""
        version = item.get("DisplayVersion") or item.get("version") or ""
        publisher = item.get("Publisher") or item.get("publisher") or ""
        fingerprint = _fingerprint(item.get("fingerprint"), name, version, publisher)
        if not fingerprint or not name:
            continue
        active.add(fingerprint)
        obj, _ = AgentSoftwareRecord.objects.get_or_create(
            agent=agent,
            fingerprint=fingerprint,
            defaults={
                "name": name,
                "version": version,
                "publisher": publisher,
                "metadata": item,
            },
        )
        obj.name = name
        obj.version = version
        obj.publisher = publisher
        obj.is_present = True
        obj.metadata = item
        obj.save()

    AgentSoftwareRecord.objects.filter(agent=agent).exclude(fingerprint__in=list(active)).update(is_present=False)


def _upsert_network(agent, items):
    active = set()
    for item in items or []:
        address = item.get("address") or item.get("ip") or item.get("mac") or ""
        mac = item.get("mac_address") or item.get("mac") or ""
        iface = item.get("interface_name") or item.get("interface") or ""
        addr_type = item.get("address_type") or ("mac" if mac and address == mac else "ipv4")
        fingerprint = _fingerprint(item.get("fingerprint"), iface, address, mac, addr_type)
        if not fingerprint or not address:
            continue
        active.add(fingerprint)
        obj, _ = AgentNetworkIdentity.objects.get_or_create(
            agent=agent,
            fingerprint=fingerprint,
            defaults={
                "interface_name": iface,
                "address": address,
                "mac_address": mac,
                "address_type": addr_type,
                "metadata": item,
            },
        )
        obj.interface_name = iface
        obj.address = address
        obj.mac_address = mac
        obj.address_type = addr_type
        obj.is_active = True
        obj.metadata = item
        obj.save()

    AgentNetworkIdentity.objects.filter(agent=agent).exclude(fingerprint__in=list(active)).update(is_active=False)


def _store_timeline_events(agent, events):
    for event in events or []:
        AgentTimelineEvent.objects.create(
            agent=agent,
            category=event.get("category", "system"),
            event_type=event.get("event_type", "observed"),
            title=event.get("title") or event.get("event_type", "observed"),
            description=event.get("description", ""),
            severity=event.get("severity", "info"),
            actor=event.get("actor", ""),
            file_path=event.get("file_path", ""),
            file_hash=event.get("file_hash", ""),
            observed_at=_parse_dt(event.get("observed_at")),
            source_service=event.get("source_service", ""),
            metadata=event.get("metadata") or {},
        )


def process_agent_inventory(agent, inventory):
    hardware = inventory.get("hardware") or []
    software = _software_from_payload(inventory)
    network = inventory.get("network") or []
    timeline_events = inventory.get("timeline_events") or []

    AgentInventorySnapshot.objects.create(agent=agent, payload=inventory)
    agent.last_inventory_at = timezone.now()
    agent.latest_inventory = inventory
    agent.save(update_fields=["last_inventory_at", "latest_inventory", "updated_at"])

    _upsert_hardware(agent, hardware)
    _upsert_software(agent, software)
    _upsert_network(agent, network)
    _store_timeline_events(agent, timeline_events)


def get_aegis_policy_payload():
    ensure_default_aegis_policy()
    policies = []
    for policy in AegisDlpPolicy.objects.filter(enabled=True).prefetch_related("rules").order_by("name"):
        policies.append(
            {
                "id": policy.id,
                "name": policy.name,
                "code": policy.code,
                "description": policy.description,
                "severity": policy.severity,
                "scan_paths": policy.scan_paths or [],
                "monitored_extensions": policy.monitored_extensions or [],
                "max_file_size_mb": policy.max_file_size_mb,
                "rules": [
                    {
                        "id": rule.id,
                        "name": rule.name,
                        "classification": rule.classification,
                        "severity": rule.severity,
                        "match_type": rule.match_type,
                        "pattern": rule.pattern,
                        "tags": rule.tags or [],
                    }
                    for rule in policy.rules.filter(enabled=True).order_by("id")
                ],
            }
        )
    return {"module": "aegis_dlp", "policies": policies}


def process_dlp_incidents(agent, payload):
    incidents = payload.get("incidents") or []
    created = []
    for item in incidents:
        policy = None
        rule = None
        if item.get("policy_code"):
            policy = AegisDlpPolicy.objects.filter(code=item.get("policy_code")).first()
        if policy and item.get("rule_name"):
            rule = policy.rules.filter(name=item.get("rule_name")).first()

        fingerprint = item.get("fingerprint") or _fingerprint(
            item.get("file_hash"),
            item.get("file_path"),
            item.get("rule_name"),
            item.get("detected_at"),
            item.get("classification"),
            item.get("actor"),
            item.get("channel"),
        )
        if not fingerprint:
            fallback_seed = json.dumps(item, sort_keys=True, default=str, ensure_ascii=True)
            fingerprint = hashlib.sha256(f"{agent.agent_id}:{fallback_seed}".encode("utf-8")).hexdigest()
            item = dict(item)
            item["fingerprint"] = fingerprint
        incident, _ = AegisDlpIncident.objects.get_or_create(
            agent=agent,
            fingerprint=fingerprint,
            defaults={
                "policy": policy,
                "rule": rule,
                "classification": item.get("classification", ""),
                "severity": item.get("severity", "high"),
                "file_name": item.get("file_name", ""),
                "file_path": item.get("file_path", ""),
                "file_hash": item.get("file_hash", ""),
                "actor": item.get("actor", ""),
                "channel": item.get("channel", ""),
                "status": item.get("status", "open"),
                "detected_at": _parse_dt(item.get("detected_at")),
                "metadata": item,
            },
        )
        if not incident.metadata:
            incident.metadata = item
            incident.save(update_fields=["metadata"])
        created.append(incident)

        AgentTimelineEvent.objects.create(
            agent=agent,
            category="dlp",
            event_type="dlp_match",
            title=f"DLP detecto {item.get('classification', 'contenido sensible')}",
            description=item.get("summary", ""),
            severity=item.get("severity", "high"),
            actor=item.get("actor", ""),
            file_path=item.get("file_path", ""),
            file_hash=item.get("file_hash", ""),
            observed_at=_parse_dt(item.get("detected_at")),
            source_service="aegis_dlp",
            metadata=item,
        )

    agent.last_dlp_at = timezone.now()
    agent.save(update_fields=["last_dlp_at", "updated_at"])
    return created
