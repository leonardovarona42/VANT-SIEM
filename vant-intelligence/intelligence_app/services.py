"""
External API integrations for Threat Intelligence.
AbuseIPDB, MAC Vendors, VirusTotal lookups with caching and quota management.
"""
import json
import logging
import os
import time
from datetime import datetime, timedelta


import requests
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import (
    IntelligenceApiKey, IntelligenceIpReport,
    IntelligenceMacLookup, IntelligenceVtReport,
)

logger = logging.getLogger(__name__)

ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
MACVENDORS_BASE = "https://api.macvendors.com/v1/lookup"
VIRUSTOTAL_BASE = "https://www.virustotal.com/api/v3"

CACHE_TTL_IP = int(os.getenv("INTELLIGENCE_CACHE_IP", "3600"))
CACHE_TTL_MAC = int(os.getenv("INTELLIGENCE_CACHE_MAC", "86400"))
CACHE_TTL_VT = int(os.getenv("INTELLIGENCE_CACHE_VT", "3600"))


def _get_api_key(provider):
    try:
        key_obj = IntelligenceApiKey.objects.get(provider=provider, enabled=True)
        if key_obj.is_quota_exhausted:
            logger.warning("quota exhausted for %s", provider)
            return None
        return key_obj
    except IntelligenceApiKey.DoesNotExist:
        logger.warning("no API key configured for %s", provider)
        return None


def _decrypt_key(encrypted):
    """Simple decrypt using service secret XOR. Override with proper encryption."""
    secret = os.getenv("SERVICE_SECRET", "changeme-service-secret")
    return "".join(chr(ord(c) ^ ord(secret[i % len(secret)])) for i, c in enumerate(encrypted))


def _encrypt_key(plain):
    secret = os.getenv("SERVICE_SECRET", "changeme-service-secret")
    return "".join(chr(ord(c) ^ ord(secret[i % len(secret)])) for i, c in enumerate(plain))


def _increment_quota(key_obj):
    key_obj.quota_used += 1
    key_obj.last_used_at = timezone.now()
    key_obj.save(update_fields=["quota_used", "last_used_at"])


# --- AbuseIPDB ---

def lookup_ip(ip_address, force=False):
    if not force:
        recent = IntelligenceIpReport.objects.filter(
            ip_address=ip_address,
            queried_at__gte=timezone.now() - timedelta(seconds=CACHE_TTL_IP),
        ).order_by("-queried_at").first()
        if recent:
            logger.debug("cache hit ip=%s", ip_address)
            return recent

    key_obj = _get_api_key("abuseipdb")
    if not key_obj:
        return None

    try:
        resp = requests.get(
            f"{ABUSEIPDB_BASE}/check",
            headers={"Key": key_obj.api_key_encrypted, "Accept": "application/json"},
            params={"ipAddress": ip_address, "maxAgeInDays": "90", "verbose": ""},
            timeout=15,
        )
        if resp.status_code == 429:
            logger.warning("abuseipdb rate limited")
            return None

        data = resp.json().get("data", {})
        if resp.status_code != 200:
            logger.error("abuseipdb error ip=%s status=%s body=%s", ip_address, resp.status_code, resp.text)
            return None

        _increment_quota(key_obj)
        report = IntelligenceIpReport.objects.create(
            ip_address=ip_address,
            is_whitelisted=data.get("isWhitelisted", False),
            abuse_confidence_score=data.get("abuseConfidenceScore", 0),
            country_code=data.get("countryCode", ""),
            country_name=data.get("countryName", ""),
            domain=data.get("domain", ""),
            total_reports=data.get("totalReports", 0),
            num_distinct_users=data.get("numDistinctUsers", 0),
            last_reported_at=data.get("lastReportedAt"),
            reports=data.get("reports", []),
        )
        logger.info("abuseipdb lookup ip=%s score=%s", ip_address, report.abuse_confidence_score)
        return report

    except requests.RequestException as e:
        logger.error("abuseipdb request failed ip=%s error=%s", ip_address, e)
        return None


def fetch_abuseipdb_blacklist(confidence_minimum=75, limit=10000):
    """Download AbuseIPDB blacklist and store each entry as IntelligenceIpReport."""
    key_obj = _get_api_key("abuseipdb")
    if not key_obj:
        logger.warning("cannot fetch blacklist: no abuseipdb api key")
        return 0

    count = 0
    page = 1
    per_page = 1000

    try:
        while True:
            remaining = limit - count
            if remaining <= 0:
                break
            take = min(per_page, remaining)

            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/blacklist",
                params={
                    "confidenceMinimum": confidence_minimum,
                    "limit": take,
                    "page": page,
                },
                headers={"Key": key_obj.api_key_encrypted, "Accept": "application/json"},
                timeout=30,
            )

            if resp.status_code == 429:
                logger.warning("abuseipdb blacklist rate limited at page=%s", page)
                break
            if resp.status_code != 200:
                logger.error("abuseipdb blacklist error status=%s body=%s", resp.status_code, resp.text[:200])
                break

            data = resp.json().get("data", [])
            if not data:
                break

            for entry in data:
                IntelligenceIpReport.objects.get_or_create(
                    ip_address=entry.get("ipAddress"),
                    defaults={
                        "abuse_confidence_score": entry.get("abuseConfidenceScore", 0),
                        "country_code": entry.get("countryCode", ""),
                        "country_name": entry.get("countryName", ""),
                        "last_reported_at": entry.get("lastReportedAt"),
                        "domain": entry.get("domain", ""),
                        "total_reports": entry.get("totalReports", 0),
                        "num_distinct_users": entry.get("numDistinctUsers", 0),
                        "is_whitelisted": entry.get("isWhitelisted", False),
                    },
                )
                count += 1

            logger.info("abuseipdb blacklist page=%s entries=%s total=%s", page, len(data), count)
            _increment_quota(key_obj)
            page += 1

    except requests.RequestException as e:
        logger.error("abuseipdb blacklist request failed error=%s", e)

    logger.info("abuseipdb blacklist done: %s entries stored", count)
    return count


def _sanitize_json(obj):
    """Remove null bytes and control chars from strings in JSON-like structures."""
    if isinstance(obj, str):
        return "".join(c for c in obj if c >= " " or c in "\n\r\t")
    elif isinstance(obj, list):
        return [_sanitize_json(item) for item in obj]
    elif isinstance(obj, dict):
        return {k: _sanitize_json(v) for k, v in obj.items()}
    return obj


def fetch_abuseipdb_reports(ip_address, max_age_days=90):
    """Get detailed reports for a specific IP from AbuseIPDB (0/100 quota)."""
    key_obj = _get_api_key("abuseipdb")
    if not key_obj:
        return None

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/reports",
            params={"ipAddress": ip_address, "maxAgeInDays": max_age_days},
            headers={"Key": key_obj.api_key_encrypted, "Accept": "application/json"},
            timeout=15,
        )
        if resp.status_code != 200:
            logger.error("abuseipdb reports error ip=%s status=%s", ip_address, resp.status_code)
            return None

        data = resp.json().get("data", {})
        results = data.get("results", [])
        if results:
            obj, _ = IntelligenceIpReport.objects.update_or_create(
                ip_address=ip_address,
                defaults={
                    "total_reports": data.get("total", 0) or data.get("count", 0),
                    "reports": _sanitize_json(results),
                    "last_reported_at": results[0].get("reportedAt") if results else None,
                },
            )
            _increment_quota(key_obj)
            logger.info("abuseipdb reports ip=%s total=%s", ip_address, data.get("total", 0))
            return obj
        return None

    except requests.RequestException as e:
        logger.error("abuseipdb reports request failed ip=%s error=%s", ip_address, e)
        return None


def fetch_abuseipdb_bulk_check(ip_list, batch_size=1000):
    """Check up to 1000 IPs per request (max 5 requests/day)."""
    key_obj = _get_api_key("abuseipdb")
    if not key_obj:
        logger.warning("cannot bulk-check: no abuseipdb api key")
        return 0

    total = 0
    for start in range(0, len(ip_list), batch_size):
        batch = ip_list[start:start + batch_size]
        try:
            resp = requests.post(
                "https://api.abuseipdb.com/api/v2/bulk-check/",
                json={"ips": batch},
                headers={"Key": key_obj.api_key_encrypted, "Accept": "application/json"},
                timeout=60,
            )
            if resp.status_code == 429:
                logger.warning("abuseipdb bulk-check rate limited at offset=%s", start)
                break
            if resp.status_code != 200:
                logger.error("abuseipdb bulk-check error status=%s body=%s", resp.status_code, resp.text[:200])
                break

            data = resp.json().get("data", [])
            for entry in data:
                ip = entry.get("ipAddress")
                if not ip:
                    continue
                IntelligenceIpReport.objects.update_or_create(
                    ip_address=ip,
                    defaults={
                        "abuse_confidence_score": entry.get("abuseConfidenceScore", 0),
                        "country_code": entry.get("countryCode", ""),
                        "country_name": entry.get("countryName", ""),
                        "domain": entry.get("domain", ""),
                        "total_reports": entry.get("totalReports", 0),
                        "num_distinct_users": entry.get("numDistinctUsers", 0),
                        "last_reported_at": entry.get("lastReportedAt"),
                        "is_whitelisted": entry.get("isWhitelisted", False),
                    },
                )
                total += 1

            logger.info("abuseipdb bulk-check batch offset=%s entries=%s total=%s", start, len(data), total)
            _increment_quota(key_obj)

        except requests.RequestException as e:
            logger.error("abuseipdb bulk-check request failed error=%s", e)
            break

    logger.info("abuseipdb bulk-check done: %s entries stored/updated", total)
    return total


# --- MAC Vendors ---

def lookup_mac(mac_address, force=False):
    if not force:
        recent = IntelligenceMacLookup.objects.filter(
            mac_address=mac_address,
            queried_at__gte=timezone.now() - timedelta(seconds=CACHE_TTL_MAC),
        ).order_by("-queried_at").first()
        if recent:
            logger.debug("cache hit mac=%s", mac_address)
            return recent

    key_obj = _get_api_key("macvendors")
    if not key_obj:
        return None

    try:
        resp = requests.get(
            f"{MACVENDORS_BASE}/{mac_address}",
            headers={"Authorization": f"Bearer {key_obj.api_key_encrypted}", "Accept": "application/json"},
            timeout=10,
        )
        if resp.status_code == 429:
            logger.warning("macvendors rate limited")
            return None

        vendor = ""
        if resp.status_code == 200:
            try:
                vendor = resp.json().get("data", {}).get("organization_name", resp.text.strip())
            except Exception:
                vendor = resp.text.strip()
        if resp.status_code not in (200, 404):
            logger.error("macvendors error mac=%s status=%s", mac_address, resp.status_code)
            return None

        _increment_quota(key_obj)
        lookup = IntelligenceMacLookup.objects.create(
            mac_address=mac_address,
            vendor=vendor,
            is_private=(resp.status_code == 404),
        )
        logger.info("macvendors lookup mac=%s vendor=%s", mac_address, vendor or "(not found)")
        return lookup

    except requests.RequestException as e:
        logger.error("macvendors request failed mac=%s error=%s", mac_address, e)
        return None


# --- VirusTotal ---

def lookup_virustotal(indicator, indicator_type, force=False):
    if not force:
        recent = IntelligenceVtReport.objects.filter(
            indicator=indicator,
            indicator_type=indicator_type,
            queried_at__gte=timezone.now() - timedelta(seconds=CACHE_TTL_VT),
        ).order_by("-queried_at").first()
        if recent:
            logger.debug("cache hit vt=%s type=%s", indicator, indicator_type)
            return recent

    key_obj = _get_api_key("virustotal")
    if not key_obj:
        return None

    endpoint_map = {
        "ip": f"ip_addresses/{indicator}",
        "domain": f"domains/{indicator}",
        "url": "urls",
        "hash": f"files/{indicator}",
    }
    endpoint = endpoint_map.get(indicator_type)
    if not endpoint:
        logger.error("unknown vt indicator_type=%s", indicator_type)
        return None

    try:
        headers = {"x-apikey": key_obj.api_key_encrypted, "Accept": "application/json"}
        params = {}

        if indicator_type == "url":
            import base64, hashlib
            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
            endpoint = f"urls/{url_id}"

        resp = requests.get(
            f"{VIRUSTOTAL_BASE}/{endpoint}",
            headers=headers,
            params=params,
            timeout=15,
        )
        if resp.status_code == 429:
            logger.warning("virustotal rate limited")
            return None

        if resp.status_code != 200:
            logger.error("virustotal error indicator=%s status=%s", indicator, resp.status_code)
            return None

        data = resp.json().get("data", {})
        attributes = data.get("attributes", {})
        last_stats = attributes.get("last_analysis_stats", {})
        reputation = attributes.get("reputation", 0)

        _increment_quota(key_obj)
        report = IntelligenceVtReport.objects.create(
            indicator=indicator,
            indicator_type=indicator_type,
            malicious=last_stats.get("malicious", 0),
            suspicious=last_stats.get("suspicious", 0),
            harmless=last_stats.get("harmless", 0),
            undetected=last_stats.get("undetected", 0),
            timeout=last_stats.get("timeout", 0),
            last_analysis_stats=last_stats,
            reputation_score=reputation,
            verbose_msg=attributes.get("verbose_msg", ""),
        )
        logger.info(
            "virustotal lookup indicator=%s type=%s malicious=%s",
            indicator, indicator_type, report.malicious,
        )
        return report

    except requests.RequestException as e:
        logger.error("virustotal request failed indicator=%s error=%s", indicator, e)
        return None


# --- Key Management ---

def configure_api_key(provider, raw_key, quota_limit=0):
    with transaction.atomic():
        key_obj, created = IntelligenceApiKey.objects.update_or_create(
            provider=provider,
            defaults={
                "api_key_encrypted": raw_key,
                "enabled": True,
                "quota_limit": quota_limit,
                "quota_used": 0,
            },
        )
        logger.info("api key %s %s", provider, "created" if created else "updated")
        return key_obj


def delete_api_key(provider):
    deleted, _ = IntelligenceApiKey.objects.filter(provider=provider).delete()
    return deleted > 0


def test_api_key(provider):
    """Test an API key by making a minimal call to the provider."""
    try:
        key_obj = IntelligenceApiKey.objects.get(provider=provider, enabled=True)
    except IntelligenceApiKey.DoesNotExist:
        return {"success": False, "message": "No hay API Key configurada para este proveedor."}

    raw_key = key_obj.api_key_encrypted
    test_configs = {
        "abuseipdb": {
            "url": "https://api.abuseipdb.com/api/v2/check",
            "params": {"ipAddress": "8.8.8.8", "maxAgeInDays": "90"},
            "headers": {"Key": raw_key, "Accept": "application/json"},
        },
        "macvendors": {
            "url": "https://api.macvendors.com/v1/lookup/FC:FB:FB:01:FA:21",
            "params": {},
            "headers": {"Authorization": f"Bearer {raw_key}", "Accept": "application/json"},
        },
        "virustotal": {
            "url": "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
            "params": {},
            "headers": {"x-apikey": raw_key, "Accept": "application/json"},
        },
    }

    config = test_configs.get(provider)
    if not config:
        return {"success": False, "message": f"Proveedor desconocido: {provider}"}

    try:
        resp = requests.get(
            config["url"],
            params=config["params"],
            headers=config["headers"],
            timeout=10,
        )
        if resp.status_code == 200:
            return {"success": True, "message": "API Key valida y funcionando.", "status_code": resp.status_code}
        elif resp.status_code == 401 or resp.status_code == 403:
            return {"success": False, "message": "API Key invalida o sin permisos.", "status_code": resp.status_code}
        elif resp.status_code == 429:
            return {"success": False, "message": "Rate limit excedido. Intenta mas tarde.", "status_code": resp.status_code}
        else:
            return {"success": False, "message": f"Error HTTP {resp.status_code}: {resp.text[:200]}", "status_code": resp.status_code}
    except requests.RequestException as e:
        return {"success": False, "message": f"Error de conexion: {e}"}
