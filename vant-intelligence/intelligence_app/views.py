import logging
from datetime import timedelta

import requests
from django.db import connection, connections
from django.db.models import Count
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .models import (
    IntelligenceApiKey, IntelligenceIpReport,
    IntelligenceMacLookup, IntelligenceVtReport, IntelligenceScanJob,
)
from .serializers import (
    IntelligenceApiKeySerializer, IntelligenceApiKeyReadSerializer,
    IntelligenceIpReportSerializer, IntelligenceIpLookupSerializer,
    IntelligenceMacLookupSerializer, IntelligenceMacLookupRequestSerializer,
    IntelligenceVtReportSerializer, IntelligenceVtLookupSerializer,
    IntelligenceScanJobSerializer, IntelligenceScanJobCreateSerializer,
)
from .services import lookup_ip, lookup_mac, lookup_virustotal, configure_api_key, delete_api_key, test_api_key

logger = logging.getLogger(__name__)


@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    try:
        connection.ensure_connection()
        db_ok = True
    except Exception:
        db_ok = False
    return Response({
        'status': 'healthy' if db_ok else 'degraded',
        'service': 'vant_intelligence',
        'database': 'connected' if db_ok else 'disconnected',
        'timestamp': timezone.now().isoformat(),
    })


@api_view(['GET'])
@permission_classes([AllowAny])
def intelligence_dashboard(request):
    """Returns aggregated stats for the Intelligence dashboard."""
    now = timezone.now()
    last_24h = now - timedelta(hours=24)

    ip_reports_24h = IntelligenceIpReport.objects.filter(queried_at__gte=last_24h).count()
    mac_lookups_24h = IntelligenceMacLookup.objects.filter(queried_at__gte=last_24h).count()
    vt_reports_24h = IntelligenceVtReport.objects.filter(queried_at__gte=last_24h).count()
    high_score_ips = IntelligenceIpReport.objects.filter(
        abuse_confidence_score__gte=50, queried_at__gte=last_24h,
    ).count()
    vt_malicious = IntelligenceVtReport.objects.filter(
        malicious__gt=0, queried_at__gte=last_24h,
    ).count()
    pending_jobs = IntelligenceScanJob.objects.filter(status='pending').count()

    keys = IntelligenceApiKey.objects.all().values('provider', 'enabled', 'quota_used', 'quota_limit', 'last_used_at')

    return Response({
        'ip_reports_24h': ip_reports_24h,
        'mac_lookups_24h': mac_lookups_24h,
        'vt_reports_24h': vt_reports_24h,
        'high_score_ips': high_score_ips,
        'vt_malicious': vt_malicious,
        'pending_jobs': pending_jobs,
        'api_keys': list(keys),
    })


@api_view(['GET'])
@permission_classes([AllowAny])
def intelligence_stats(request):
    """Returns global statistics for intelligence service."""
    total_ips = IntelligenceIpReport.objects.count()
    total_macs = IntelligenceMacLookup.objects.count()
    total_vts = IntelligenceVtReport.objects.count()
    total_jobs = IntelligenceScanJob.objects.count()

    return Response({
        'total_ip_reports': total_ips,
        'total_mac_lookups': total_macs,
        'total_vt_reports': total_vts,
        'total_scan_jobs': total_jobs,
    })


# --- AbuseIPDB ---

@api_view(['GET'])
@permission_classes([AllowAny])
def ip_lookup(request):
    serializer = IntelligenceIpLookupSerializer(data=request.query_params)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    ip = serializer.validated_data['ip']
    force = request.query_params.get('force', '').lower() in ('true', '1')

    try:
        report = lookup_ip(ip, force=force)
        if report is None:
            return Response(
                {'error': 'Lookup failed. Check API key or network.'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        serialized = IntelligenceIpReportSerializer(report)
        return Response(serialized.data)
    except Exception as e:
        logger.exception("ip_lookup error ip=%s", ip)
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([AllowAny])
def ip_report_list(request):
    ips = IntelligenceIpReport.objects.all().order_by('-queried_at')
    page = request.query_params.get('page', 1)
    page_size = request.query_params.get('page_size', 50)

    try:
        page = int(page)
        page_size = min(int(page_size), 200)
    except (ValueError, TypeError):
        page = 1
        page_size = 50

    start = (page - 1) * page_size
    end = start + page_size
    total = ips.count()
    results = ips[start:end]

    serialized = IntelligenceIpReportSerializer(results, many=True)
    return Response({
        'count': total,
        'page': page,
        'page_size': page_size,
        'results': serialized.data,
    })


@api_view(['GET'])
@permission_classes([AllowAny])
def ip_report_detail(request, pk):
    try:
        report = IntelligenceIpReport.objects.get(pk=pk)
    except IntelligenceIpReport.DoesNotExist:
        return Response({'error': 'Not found'}, status=404)
    serialized = IntelligenceIpReportSerializer(report)
    return Response(serialized.data)


# --- MAC Vendors ---

@api_view(['GET'])
@permission_classes([AllowAny])
def mac_lookup(request):
    serializer = IntelligenceMacLookupRequestSerializer(data=request.query_params)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    mac = serializer.validated_data['mac']
    force = request.query_params.get('force', '').lower() in ('true', '1')

    try:
        result = lookup_mac(mac, force=force)
        if result is None:
            return Response(
                {'error': 'Lookup failed. Check API key or network.'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        serialized = IntelligenceMacLookupSerializer(result)
        return Response(serialized.data)
    except Exception as e:
        logger.exception("mac_lookup error mac=%s", mac)
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# --- VirusTotal ---

@api_view(['GET'])
@permission_classes([AllowAny])
def vt_lookup(request):
    serializer = IntelligenceVtLookupSerializer(data=request.query_params)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    indicator = serializer.validated_data['indicator']
    indicator_type = serializer.validated_data['indicator_type']
    force = request.query_params.get('force', '').lower() in ('true', '1')

    try:
        report = lookup_virustotal(indicator, indicator_type, force=force)
        if report is None:
            return Response(
                {'error': 'Lookup failed. Check API key or network.'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        serialized = IntelligenceVtReportSerializer(report)
        return Response(serialized.data)
    except Exception as e:
        logger.exception("vt_lookup error indicator=%s", indicator)
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# --- API Key Management ---

@api_view(['GET'])
@permission_classes([AllowAny])
def api_key_list(request):
    keys = IntelligenceApiKey.objects.all().order_by('provider')
    serialized = IntelligenceApiKeyReadSerializer(keys, many=True)
    return Response(serialized.data)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([AllowAny])
def api_key_detail(request, provider):
    if provider not in dict(IntelligenceApiKey.PROVIDER_CHOICES):
        return Response({'error': f'Invalid provider: {provider}'}, status=400)

    if request.method == 'GET':
        try:
            key = IntelligenceApiKey.objects.get(provider=provider)
        except IntelligenceApiKey.DoesNotExist:
            return Response({'error': 'Not found'}, status=404)
        serialized = IntelligenceApiKeyReadSerializer(key)
        return Response(serialized.data)

    elif request.method == 'PUT':
        raw_key = request.data.get('api_key', '')
        quota_limit = request.data.get('quota_limit', 0)
        if not raw_key:
            return Response({'error': 'api_key required'}, status=400)
        try:
            key = configure_api_key(provider, raw_key, quota_limit=int(quota_limit))
            serialized = IntelligenceApiKeyReadSerializer(key)
            return Response(serialized.data)
        except Exception as e:
            return Response({'error': str(e)}, status=500)

    elif request.method == 'DELETE':
        deleted = delete_api_key(provider)
        if deleted:
            return Response({'status': 'deleted'})
        return Response({'error': 'Not found'}, status=404)


@api_view(['POST'])
@permission_classes([AllowAny])
def api_key_test(request, provider):
    if provider not in dict(IntelligenceApiKey.PROVIDER_CHOICES):
        return Response({'error': f'Invalid provider: {provider}'}, status=400)
    result = test_api_key(provider)
    status_code = status.HTTP_200_OK if result.get("success") else status.HTTP_400_BAD_REQUEST
    return Response(result, status=status_code)


# --- Scan Jobs (SOAR placeholder) ---

@api_view(['GET'])
@permission_classes([AllowAny])
def scan_job_list(request):
    jobs = IntelligenceScanJob.objects.all().order_by('-created_at')
    status_filter = request.query_params.get('status')
    if status_filter:
        jobs = jobs.filter(status=status_filter)

    page = request.query_params.get('page', 1)
    page_size = request.query_params.get('page_size', 50)

    try:
        page = int(page)
        page_size = min(int(page_size), 200)
    except (ValueError, TypeError):
        page = 1
        page_size = 50

    start = (page - 1) * page_size
    end = start + page_size
    total = jobs.count()
    results = jobs[start:end]

    serialized = IntelligenceScanJobSerializer(results, many=True)
    return Response({
        'count': total,
        'page': page,
        'page_size': page_size,
        'results': serialized.data,
    })


@api_view(['GET'])
@permission_classes([AllowAny])
def scan_job_detail(request, pk):
    try:
        job = IntelligenceScanJob.objects.get(pk=pk)
    except IntelligenceScanJob.DoesNotExist:
        return Response({'error': 'Not found'}, status=404)
    serialized = IntelligenceScanJobSerializer(job)
    return Response(serialized.data)


@api_view(['POST'])
@permission_classes([AllowAny])
def scan_job_create(request):
    serializer = IntelligenceScanJobCreateSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    job = IntelligenceScanJob.objects.create(
        job_type=serializer.validated_data['job_type'],
        target=serializer.validated_data['target'],
        status='pending',
    )
    serialized = IntelligenceScanJobSerializer(job)
    return Response(serialized.data, status=status.HTTP_201_CREATED)


@api_view(['GET'])
@permission_classes([AllowAny])
def analytics_dashboard(request):
    hours = int(request.GET.get('hours', 24))
    since = timezone.now() - timedelta(hours=hours)

    try:
        with connections['vant_logs'].cursor() as cursor:
            cursor.execute("""
                SELECT
                    parsed_fields->>'src_ip' AS ip,
                    parsed_fields->>'dst_port' AS port,
                    parsed_fields->>'protocol' AS proto,
                    parsed_fields->>'event_type' AS event_type,
                    parsed_fields->>'src_port' AS src_port,
                    event_time,
                    parsed_fields->>'dest_ip' AS dest_ip
                FROM logs_events_raw
                WHERE source_type = 'suricata'
                  AND parsed_fields ? 'src_ip'
                  AND event_time >= %s
                ORDER BY event_time DESC
            """, [since])

            rows = cursor.fetchall()
    except Exception as e:
        logger.error("vant_logs query failed: %s", e)
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    if not rows:
        return Response({
            "stats": {
                "total_events": 0,
                "unique_ips": 0,
                "external_ips": 0,
                "known_malicious": 0,
                "malicious_ips": [],
                "top_internal_ips": [],
                "top_ports": [],
                "top_protocols": [],
                "timeline": [],
                "summary": {
                    "abuse_high": 0,
                    "abuse_medium": 0,
                    "vt_detected": 0,
                }
            }
        })

    def is_private_ip(ip):
        if not ip:
            return False
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        if parts[0] == "10":
            return True
        if parts[0] == "172" and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
            return True
        if parts[0] == "192" and parts[1] == "168":
            return True
        if parts[0] == "127":
            return True
        return False

    all_ips_set = set()
    for row in rows:
        ip, _, _, _, _, _, dest_ip = row
        if ip:
            all_ips_set.add(ip)
        if dest_ip:
            all_ips_set.add(dest_ip)

    all_ips = list(all_ips_set)

    abuse_records = {
        r.ip_address: r
        for r in IntelligenceIpReport.objects.filter(
            ip_address__in=all_ips
        ).exclude(abuse_confidence_score__isnull=True).order_by('-abuse_confidence_score')
    }

    vt_records = {
        r.indicator: r
        for r in IntelligenceVtReport.objects.filter(
            indicator__in=all_ips
        )
    }

    all_malicious_ips = set(abuse_records.keys()) | set(vt_records.keys())

    external_ips = [ip for ip in all_ips if not is_private_ip(ip)]
    internal_ips = [ip for ip in all_ips if is_private_ip(ip)]

    malicious_ip_set = {ip for ip in external_ips if ip in all_malicious_ips}

    ip_stats = {}
    ip_ports = {}
    ip_protos = {}
    timeline_buckets = {}

    for row in rows:
        ip, port, proto, ev_type, src_port, ev_time, dest_ip = row
        src = ip or ""
        dst = dest_ip or ""

        for which_ip in [src, dst]:
            if which_ip:
                ip_stats.setdefault(which_ip, {"total": 0, "src_count": 0, "dst_count": 0, "events": []})
                ip_stats[which_ip]["total"] += 1
                if port:
                    ip_ports.setdefault(which_ip, set()).add(port)
                if proto:
                    ip_protos.setdefault(which_ip, set()).add(proto)
                ip_stats[which_ip]["events"].append({
                    "port": port,
                    "proto": proto,
                    "event_type": ev_type,
                    "time": ev_time.isoformat() if ev_time and hasattr(ev_time, 'isoformat') else None,
                })

        bucket = ev_time.strftime("%Y-%m-%dT%H:00") if ev_time and hasattr(ev_time, 'strftime') else "unknown"
        timeline_buckets.setdefault(bucket, {"time": bucket, "total": 0, "malicious": 0})
        timeline_buckets[bucket]["total"] += 1
        if src in all_malicious_ips or dst in all_malicious_ips:
            timeline_buckets[bucket]["malicious"] += 1

    malicious_ips = []
    for ip in sorted(malicious_ip_set, key=lambda x: -ip_stats.get(x, {}).get("total", 0)):
        score = 0
        abuse_conf = 0
        vt_malicious = 0
        vt_suspicious = 0
        abuse_record = abuse_records.get(ip)
        vt_record = vt_records.get(ip)

        if abuse_record:
            abuse_conf = abuse_record.abuse_confidence_score or 0
            if abuse_conf >= 75:
                score += 3
            elif abuse_conf >= 50:
                score += 2
            elif abuse_conf >= 25:
                score += 1

        if vt_record:
            vt_malicious = vt_record.malicious or 0
            vt_suspicious = vt_record.suspicious or 0
            if vt_malicious > 0:
                score += 3
            if vt_suspicious > 0:
                score += 1

        stat = ip_stats.get(ip, {"total": 0, "events": []})
        malicious_ips.append({
            "ip": ip,
            "score": score,
            "events": stat["total"],
            "abuse_confidence_score": abuse_conf,
            "vt_malicious": vt_malicious,
            "vt_suspicious": vt_suspicious,
            "ports": sorted(ip_ports.get(ip, set())),
            "protocols": sorted(ip_protos.get(ip, set())),
            "first_seen": stat["events"][0]["time"] if stat["events"] else None,
            "last_seen": stat["events"][-1]["time"] if stat["events"] else None,
        })

    malicious_ips.sort(key=lambda x: (-x["score"], -x["events"]))

    internal_stats = []
    for ip in sorted(internal_ips, key=lambda x: -ip_stats.get(x, {}).get("total", 0))[:20]:
        stat = ip_stats.get(ip, {"total": 0})
        internal_stats.append({
            "ip": ip,
            "events": stat["total"],
            "ports": sorted(ip_ports.get(ip, set())),
            "protocols": sorted(ip_protos.get(ip, set())),
        })

    port_counts = {}
    for row in rows:
        ip, port, proto, ev_type, src_port, ev_time, dest_ip = row
        if not port:
            continue
        is_mal = (ip and ip in all_malicious_ips) or (dest_ip and dest_ip in all_malicious_ips)
        port_counts.setdefault(port, {"port": port, "total": 0, "malicious": 0})
        port_counts[port]["total"] += 1
        if is_mal:
            port_counts[port]["malicious"] += 1

    top_ports = sorted(port_counts.values(), key=lambda x: -x["total"])[:15]

    proto_counts = {}
    for row in rows:
        _, _, proto, _, _, _, _ = row
        if proto:
            proto_counts[proto] = proto_counts.get(proto, 0) + 1
    top_protocols = sorted(proto_counts.items(), key=lambda x: -x[1])[:10]
    top_protocols = [{"protocol": p, "count": c} for p, c in top_protocols]

    timeline = sorted(timeline_buckets.values(), key=lambda x: x["time"])

    summary = {
        "abuse_high": sum(1 for r in abuse_records.values() if (r.abuse_confidence_score or 0) >= 75),
        "abuse_medium": sum(1 for r in abuse_records.values() if 25 <= (r.abuse_confidence_score or 0) < 75),
        "vt_detected": sum(1 for r in vt_records.values() if r.malicious > 0),
    }

    return Response({
        "stats": {
            "total_events": len(rows),
            "unique_ips": len(all_ips),
            "external_ips": len(external_ips),
            "known_malicious": len(malicious_ips),
            "malicious_ips": malicious_ips[:50],
            "top_internal_ips": internal_stats,
            "top_ports": top_ports,
            "top_protocols": top_protocols,
            "timeline": timeline,
            "summary": summary,
        }
    })


COUNTRY_COORDS = {
    "US": {"lat": 39.8283, "lon": -98.5795, "name": "United States"},
    "DE": {"lat": 51.1657, "lon": 10.4515, "name": "Germany"},
    "CN": {"lat": 35.8617, "lon": 104.1954, "name": "China"},
    "NL": {"lat": 52.1326, "lon": 5.2913, "name": "Netherlands"},
    "IN": {"lat": 20.5937, "lon": 78.9629, "name": "India"},
    "GB": {"lat": 55.3781, "lon": -3.4360, "name": "United Kingdom"},
    "KR": {"lat": 35.9078, "lon": 127.7669, "name": "South Korea"},
    "SG": {"lat": 1.3521, "lon": 103.8198, "name": "Singapore"},
    "FR": {"lat": 46.6034, "lon": 1.8883, "name": "France"},
    "BR": {"lat": -14.2350, "lon": -51.9253, "name": "Brazil"},
    "HK": {"lat": 22.3193, "lon": 114.1694, "name": "Hong Kong"},
    "JP": {"lat": 36.2048, "lon": 138.2529, "name": "Japan"},
    "RO": {"lat": 45.9432, "lon": 24.9668, "name": "Romania"},
    "VN": {"lat": 14.0583, "lon": 108.2772, "name": "Vietnam"},
    "RU": {"lat": 61.5240, "lon": 105.3188, "name": "Russia"},
    "ID": {"lat": -0.7893, "lon": 113.9213, "name": "Indonesia"},
    "SE": {"lat": 60.1282, "lon": 18.6435, "name": "Sweden"},
    "CA": {"lat": 56.1304, "lon": -106.3468, "name": "Canada"},
    "AU": {"lat": -25.2744, "lon": 133.7751, "name": "Australia"},
    "PL": {"lat": 51.9194, "lon": 19.1451, "name": "Poland"},
    "TH": {"lat": 15.8700, "lon": 100.9925, "name": "Thailand"},
    "IT": {"lat": 41.8719, "lon": 12.5674, "name": "Italy"},
    "ES": {"lat": 40.4637, "lon": -3.7492, "name": "Spain"},
    "UA": {"lat": 48.3794, "lon": 31.1656, "name": "Ukraine"},
    "CZ": {"lat": 49.8175, "lon": 15.4730, "name": "Czech Republic"},
    "IE": {"lat": 53.4129, "lon": -8.2439, "name": "Ireland"},
    "CH": {"lat": 46.8182, "lon": 8.2275, "name": "Switzerland"},
    "AT": {"lat": 47.5162, "lon": 14.5501, "name": "Austria"},
    "AR": {"lat": -38.4161, "lon": -63.6167, "name": "Argentina"},
    "MX": {"lat": 23.6345, "lon": -102.5528, "name": "Mexico"},
    "ZA": {"lat": -30.5595, "lon": 22.9375, "name": "South Africa"},
    "TR": {"lat": 38.9637, "lon": 35.2433, "name": "Turkey"},
    "IL": {"lat": 31.0461, "lon": 34.8516, "name": "Israel"},
    "EG": {"lat": 26.8206, "lon": 30.8025, "name": "Egypt"},
    "NG": {"lat": 9.0820, "lon": 8.6753, "name": "Nigeria"},
    "PH": {"lat": 12.8797, "lon": 121.7740, "name": "Philippines"},
    "MY": {"lat": 4.2105, "lon": 101.9758, "name": "Malaysia"},
    "TW": {"lat": 23.6978, "lon": 120.9605, "name": "Taiwan"},
    "CL": {"lat": -35.6751, "lon": -71.5430, "name": "Chile"},
    "CO": {"lat": 4.5709, "lon": -74.2973, "name": "Colombia"},
    "PE": {"lat": -9.1900, "lon": -75.0152, "name": "Peru"},
    "VN": {"lat": 14.0583, "lon": 108.2772, "name": "Vietnam"},
    "NO": {"lat": 60.4720, "lon": 8.4689, "name": "Norway"},
    "DK": {"lat": 56.2639, "lon": 9.5018, "name": "Denmark"},
    "FI": {"lat": 61.9241, "lon": 25.7482, "name": "Finland"},
    "PT": {"lat": 39.3999, "lon": -8.2245, "name": "Portugal"},
    "BE": {"lat": 50.8503, "lon": 4.3517, "name": "Belgium"},
    "GR": {"lat": 39.0742, "lon": 21.8243, "name": "Greece"},
    "HU": {"lat": 47.1625, "lon": 19.5033, "name": "Hungary"},
    "BG": {"lat": 42.7339, "lon": 25.4858, "name": "Bulgaria"},
    "KE": {"lat": -0.0236, "lon": 37.9062, "name": "Kenya"},
}

GEOIP_CACHE = {}

def _geoip_lookup(ip):
    if ip in GEOIP_CACHE:
        return GEOIP_CACHE[ip]
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,countryCode,lat,lon,country", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                result = {
                    "country_code": data.get("countryCode", ""),
                    "country": data.get("country", ""),
                    "lat": data.get("lat", 0),
                    "lon": data.get("lon", 0),
                }
                GEOIP_CACHE[ip] = result
                return result
    except Exception:
        pass
    return None


@api_view(['GET'])
@permission_classes([AllowAny])
def analytics_geo(request):
    hours = int(request.GET.get('hours', 24))
    since = timezone.now() - timedelta(hours=hours)

    try:
        with connections['vant_logs'].cursor() as cursor:
            cursor.execute("""
                SELECT
                    parsed_fields->>'src_ip' AS src_ip,
                    parsed_fields->>'dest_ip' AS dest_ip,
                    parsed_fields->>'dst_port' AS port,
                    parsed_fields->>'protocol' AS proto,
                    event_time
                FROM logs_events_raw
                WHERE source_type = 'suricata'
                  AND parsed_fields ? 'src_ip'
                  AND parsed_fields ? 'dest_ip'
                  AND event_time >= %s
                ORDER BY event_time DESC
            """, [since])
            rows = cursor.fetchall()
    except Exception as e:
        logger.error("vant_logs geo query failed: %s", e)
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    if not rows:
        return Response({
            "countries": [],
            "flows": [],
            "stats": {"total_countries": 0, "total_flows": 0, "total_events": 0}
        })

    def is_private_ip(ip):
        if not ip:
            return False
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        if parts[0] == "10":
            return True
        if parts[0] == "172" and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
            return True
        if parts[0] == "192" and parts[1] == "168":
            return True
        if parts[0] == "127":
            return True
        return False

    # Collect all external IPs
    external_ips = set()
    for row in rows:
        src, dst = row[0], row[1]
        if src and not is_private_ip(src):
            external_ips.add(src)
        if dst and not is_private_ip(dst):
            external_ips.add(dst)

    # Lookup country info for all external IPs
    abuse_countries = {
        r.ip_address: r.country_code or ""
        for r in IntelligenceIpReport.objects.filter(
            ip_address__in=list(external_ips)
        ).exclude(country_code__isnull=True).exclude(country_code="")
    }

    ip_country = {}
    for ip in external_ips:
        cc = abuse_countries.get(ip, "")
        if cc:
            coords = COUNTRY_COORDS.get(cc, {"lat": 0, "lon": 0, "name": cc})
            ip_country[ip] = {"code": cc, "name": coords["name"], "lat": coords["lat"], "lon": coords["lon"]}
        else:
            geo = _geoip_lookup(ip)
            if geo and geo["country_code"]:
                cc = geo["country_code"]
                coords = COUNTRY_COORDS.get(cc, {"lat": geo["lat"], "lon": geo["lon"], "name": geo["country"]})
                ip_country[ip] = {"code": cc, "name": coords["name"], "lat": coords["lat"], "lon": coords["lon"]}
            else:
                ip_country[ip] = {"code": "XX", "name": "Unknown", "lat": 0, "lon": 0}

    # Aggregate by country (src -> dst flows)
    country_events = {}
    country_flows = {}
    src_country_counts = {}
    dst_country_counts = {}
    mal_ips = {
        r.ip_address
        for r in IntelligenceIpReport.objects.filter(
            ip_address__in=list(external_ips),
            abuse_confidence_score__gte=75,
        )
    }

    for row in rows:
        src_ip, dst_ip, port, proto, ev_time = row
        src_info = ip_country.get(src_ip) if src_ip and not is_private_ip(src_ip) else None
        dst_info = ip_country.get(dst_ip) if dst_ip and not is_private_ip(dst_ip) else None

        if not src_info and not dst_info:
            continue

        if src_info:
            cc = src_info["code"]
            src_country_counts[cc] = src_country_counts.get(cc, 0) + 1
            country_events.setdefault(cc, {
                "code": cc, "name": src_info["name"],
                "lat": src_info["lat"], "lon": src_info["lon"],
                "total": 0, "malicious": 0, "src_count": 0, "dst_count": 0
            })
            country_events[cc]["total"] += 1
            country_events[cc]["src_count"] += 1
            if src_ip in mal_ips:
                country_events[cc]["malicious"] += 1

        if dst_info:
            cc = dst_info["code"]
            dst_country_counts[cc] = dst_country_counts.get(cc, 0) + 1
            country_events.setdefault(cc, {
                "code": cc, "name": dst_info["name"],
                "lat": dst_info["lat"], "lon": dst_info["lon"],
                "total": 0, "malicious": 0, "src_count": 0, "dst_count": 0
            })
            country_events[cc]["total"] += 1
            country_events[cc]["dst_count"] += 1
            if dst_ip in mal_ips:
                country_events[cc]["malicious"] += 1

        if src_info and dst_info and src_info["code"] != dst_info["code"]:
            flow_key = f"{src_info['code']}->{dst_info['code']}"
            if flow_key not in country_flows:
                country_flows[flow_key] = {
                    "src_code": src_info["code"], "src_name": src_info["name"],
                    "src_lat": src_info["lat"], "src_lon": src_info["lon"],
                    "dst_code": dst_info["code"], "dst_name": dst_info["name"],
                    "dst_lat": dst_info["lat"], "dst_lon": dst_info["lon"],
                    "count": 0, "malicious": 0, "ports": set(),
                }
            country_flows[flow_key]["count"] += 1
            if src_ip in mal_ips or dst_ip in mal_ips:
                country_flows[flow_key]["malicious"] += 1
            if port:
                country_flows[flow_key]["ports"].add(port)

    # Convert sets to lists for JSON serialization
    for f in country_flows.values():
        f["ports"] = sorted(f["ports"])

    countries = sorted(country_events.values(), key=lambda x: -x["total"])
    flows = sorted(country_flows.values(), key=lambda x: -x["count"])

    return Response({
        "countries": countries[:50],
        "flows": flows[:100],
        "stats": {
            "total_countries": len(countries),
            "total_flows": len(flows),
            "total_events": len(rows),
            "source_countries": len(src_country_counts),
            "dest_countries": len(dst_country_counts),
        }
    })
