import json
import logging
import os
from datetime import datetime, timedelta

from django.db import connection
from django.db.models import Count, Q, Min, Max
from django.db.models.expressions import RawSQL
from django.db.models.fields.json import KeyTextTransform
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .models import LogSource, LogEventRaw, LogRetentionPolicy
from .serializers import (
    LogSourceSerializer, LogEventListSerializer, LogEventDetailSerializer,
    LogBulkIngestSerializer, LogRetentionPolicySerializer,
)
from .parsers import get_parser

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
        'service': 'vant_logs',
        'database': 'connected' if db_ok else 'disconnected',
        'timestamp': timezone.now().isoformat(),
    })


@api_view(['POST'])
@permission_classes([AllowAny])
def ingest_bulk(request):
    serializer = LogBulkIngestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    events = serializer.validated_data['events']
    if not events:
        return Response({'status': 'ok', 'ingested': 0}, status=status.HTTP_201_CREATED)

    agent_id = events[0].get('agent_id', '')
    if not agent_id:
        return Response(
            {'error': 'agent_id is required. Enroll the agent first.'},
            status=status.HTTP_403_FORBIDDEN,
        )

    try:
        source = LogSource.objects.get(source_id=agent_id)
        if not source.enabled:
            return Response(
                {'error': f'Agent source {agent_id} is disabled'},
                status=status.HTTP_403_FORBIDDEN,
            )
    except LogSource.DoesNotExist:
        return Response(
            {'error': f'Agent {agent_id} not found as log source. Enroll the agent first.'},
            status=status.HTTP_403_FORBIDDEN,
        )

    source.touch()
    events_to_create = []
    alerts = []
    now = timezone.now()

    for event in events:
        raw_payload = event.get('raw_payload', {})
        if isinstance(raw_payload, dict):
            raw_str = json.dumps(raw_payload)
        elif isinstance(raw_payload, str):
            raw_str = raw_payload
        else:
            raw_str = str(raw_payload)

        event_time_str = event.get('event_time')
        if event_time_str and isinstance(event_time_str, str):
            try:
                event_time = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
            except ValueError:
                event_time = now
        else:
            event_time = now

        event_source_type = event.get('source_type') or source.source_type

        try:
            parser = get_parser(event_source_type)
            parsed = parser.parse(raw_str)
        except Exception:
            parsed = None

        if parsed and isinstance(parsed, dict):
            log_event = LogEventRaw(
                source=source,
                source_type=event_source_type,
                raw_payload=raw_payload,
                event_time=parsed.get('event_time_dt', event_time),
                event_category=parsed.get('event_category', event.get('event_category', 'generic')),
                severity=parsed.get('severity', event.get('severity', 'info')),
                host_ip=parsed.get('host_ip', '') or event.get('host_ip', ''),
                host_name=parsed.get('host_name', '') or event.get('host_name', ''),
                message=parsed.get('message', event.get('message', ''))[:512],
                parsed_fields=parsed.get('parsed_fields', {}),
                tags=parsed.get('tags', []) or event.get('tags', []),
            )
        else:
            log_event = LogEventRaw(
                source=source,
                source_type=event_source_type,
                raw_payload=raw_payload,
                event_time=event_time,
                event_category=event.get('event_category', 'generic'),
                severity=event.get('severity', 'info'),
                host_ip=event.get('host_ip', ''),
                host_name=event.get('host_name', ''),
                message=event.get('message', '')[:512],
                parsed_fields=event.get('parsed_fields', {}),
                tags=event.get('tags', []),
            )
        events_to_create.append(log_event)

        if log_event.severity in ('critical', 'high'):
            alerts.append({
                'source_type': event_source_type,
                'severity': log_event.severity,
                'category': log_event.event_category,
                'host_ip': log_event.host_ip,
                'source_id': agent_id,
            })

    created = LogEventRaw.bulk_create_events(events_to_create)

    if alerts:
        try:
            from vant_common.bus import EventBus
            bus = EventBus('vant_logs')
            for alert in alerts:
                bus.publish_alert(
                    severity=alert['severity'],
                    title=f"Alert: {alert['category']} from {alert['source_id']}",
                    message=f"High/critical event from {alert['source_id']} ({alert['source_type']})",
                    source=alert['source_id'],
                    metadata=alert,
                )
        except Exception as e:
            logger.warning(f'Failed to publish alerts to bus: {e}')

    return Response({
        'status': 'ok',
        'ingested': created,
        'alerts_triggered': len(alerts),
    }, status=status.HTTP_201_CREATED)


@api_view(['POST'])
@permission_classes([AllowAny])
def upsert_source(request):
    data = request.data
    source_id = data.get('source_id')
    if not source_id:
        return Response(
            {'error': 'source_id is required'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    source, created = LogSource.objects.get_or_create(
        source_id=source_id,
        defaults={
            'source_type': data.get('source_type', 'generic_syslog'),
            'vendor': data.get('vendor', 'Unknown'),
            'model': data.get('model', ''),
            'host_name': data.get('host_name', ''),
            'host_ip': data.get('host_ip'),
            'protocol': data.get('protocol', 'http_post'),
            'port': data.get('port'),
            'api_key': data.get('api_key', ''),
            'enabled': data.get('enabled', True),
            'meta': data.get('meta', {}),
        },
    )

    if not created:
        update_fields = []
        for field in ('source_type', 'vendor', 'model', 'host_name', 'host_ip',
                       'protocol', 'port', 'api_key', 'enabled', 'meta'):
            if field in data:
                setattr(source, field, data[field])
                update_fields.append(field)
        if update_fields:
            source.save(update_fields=update_fields)

    source.touch()

    return Response({
        'status': 'ok',
        'source_id': source.source_id,
        'created': created,
    }, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([AllowAny])
def source_list(request):
    sources = LogSource.objects.all()
    source_type = request.query_params.get('source_type')
    enabled = request.query_params.get('enabled')
    if source_type:
        sources = sources.filter(source_type=source_type)
    if enabled is not None:
        sources = sources.filter(enabled=enabled.lower() == 'true')
    data = list(sources.values(
        'source_id', 'source_type', 'vendor', 'host_name', 'host_ip',
        'protocol', 'enabled', 'last_seen_at',
    ))
    return Response({'count': len(data), 'results': data})


def _parse_time_range(request):
    from_str = request.query_params.get('from')
    to_str = request.query_params.get('to')
    hours = request.query_params.get('hours')
    minutes = request.query_params.get('minutes')
    if from_str:
        try:
            dt_from = datetime.fromisoformat(from_str.replace('Z', '+00:00'))
        except (ValueError, TypeError):
            dt_from = None
    else:
        dt_from = None
    if to_str:
        try:
            dt_to = datetime.fromisoformat(to_str.replace('Z', '+00:00'))
        except (ValueError, TypeError):
            dt_to = None
    else:
        dt_to = None
    if dt_from and dt_to:
        return dt_from, dt_to
    if dt_from:
        return dt_from, timezone.now()
    if dt_to:
        return dt_to - timedelta(hours=24), dt_to
    if minutes:
        delta = timedelta(minutes=int(minutes))
    elif hours:
        delta = timedelta(hours=int(hours))
    else:
        delta = timedelta(minutes=15)
    now = timezone.now()
    return now - delta, now


@api_view(['GET'])
@permission_classes([AllowAny])
def source_type_list(request):
    dt_from, dt_to = _parse_time_range(request)
    qs = LogEventRaw.objects.filter(event_time__gte=dt_from, event_time__lte=dt_to)
    rows = (
        qs.values('source_type')
        .annotate(
            event_count=Count('id'),
            latest_event=Max('event_time'),
        )
        .order_by('-event_count')
    )
    results = []
    for row in rows:
        st = row['source_type'] or 'unknown'
        results.append({
            'source_type': st,
            'event_count': row['event_count'],
            'latest_event': str(row['latest_event']),
        })
    return Response({'count': len(results), 'results': results})


@api_view(['GET'])
@permission_classes([AllowAny])
def source_host_ips(request):
    dt_from, dt_to = _parse_time_range(request)
    qs = LogEventRaw.objects.filter(event_time__gte=dt_from, event_time__lte=dt_to, host_ip__isnull=False)
    rows = (
        qs.values('host_ip')
        .annotate(
            event_count=Count('id'),
            latest_event=Max('event_time'),
        )
        .order_by('-event_count')
    )
    results = []
    for row in rows:
        ip = row['host_ip']
        results.append({
            'host_ip': str(ip),
            'event_count': row['event_count'],
            'latest_event': str(row['latest_event']),
        })
    return Response({'count': len(results), 'results': results})


@api_view(['GET'])
@permission_classes([AllowAny])
def field_values(request):
    dt_from, dt_to = _parse_time_range(request)
    qs = LogEventRaw.objects.filter(event_time__gte=dt_from, event_time__lte=dt_to)

    source_type = request.query_params.get('source_type')
    if source_type:
        qs = qs.filter(source_type=source_type)

    fields = {
        'host_name': qs.exclude(host_name='').values_list('host_name', flat=True).distinct()[:50],
        'host_ip': qs.exclude(host_ip__isnull=True).values_list('host_ip', flat=True).distinct()[:50],
        'severity': qs.values_list('severity', flat=True).distinct(),
        'event_category': qs.exclude(event_category='').values_list('event_category', flat=True).distinct()[:50],
    }

    result = {}
    for field_name, qs_values in fields.items():
        counts_qs = qs
        if field_name == 'host_ip':
            counts_qs = qs.exclude(host_ip__isnull=True)
        elif field_name != 'severity':
            counts_qs = qs.exclude(**{field_name: ''})

        distinct_counts = list(
            counts_qs.values(field_name)
            .annotate(count=Count('id'))
            .order_by('-count')[:30]
        )
        result[field_name] = [
            {'value': str(r[field_name]) if r[field_name] is not None else '', 'count': r['count']}
            for r in distinct_counts
        ]

    return Response(result)


@api_view(['GET'])
@permission_classes([AllowAny])
def event_list(request):
    qs = LogEventRaw.objects.select_related('source').all()

    source_type = request.query_params.get('source_type')
    severity = request.query_params.get('severity')
    host_ip = request.query_params.get('host_ip')
    host_name = request.query_params.get('host_name')
    category = request.query_params.get('category')
    event_category = request.query_params.get('event_category')
    search = request.query_params.get('q')
    exclude_host_ip = request.query_params.get('exclude_host_ip')
    ordering = request.query_params.get('ordering', '-event_time')
    page = request.query_params.get('page', 1)
    page_size = min(int(request.query_params.get('page_size', 50)), 200)

    if source_type:
        qs = qs.filter(source_type=source_type)

    # Generic include/exclude filters via query_list
    for key in ('severity', 'host_ip', 'host_name', 'event_category'):
        vals = request.query_params.getlist(f'include_{key}')
        for v in vals:
            if v:
                qs = qs.filter(**{key: v})
        vals = request.query_params.getlist(f'exclude_{key}')
        for v in vals:
            if v:
                qs = qs.exclude(**{key: v})

    # Apply original single-value params for backwards compat
    if severity and 'include_severity' not in request.query_params:
        qs = qs.filter(severity=severity)
    if host_ip and 'include_host_ip' not in request.query_params:
        qs = qs.filter(host_ip=host_ip)
    if host_name and 'include_host_name' not in request.query_params:
        qs = qs.filter(host_name=host_name)
    if event_category and 'include_event_category' not in request.query_params:
        qs = qs.filter(event_category=event_category)
    elif category:
        qs = qs.filter(event_category=category)
    if exclude_host_ip:
        qs = qs.exclude(host_ip__isnull=True)
    if search:
        qs = qs.filter(Q(message__icontains=search) | Q(host_name__icontains=search))

    # Generic parsed_fields include/exclude filters
    pf_map = {
        'src_ip': 'parsed_fields__src_ip',
        'dest_ip': 'parsed_fields__dest_ip',
        'protocol': 'parsed_fields__protocol',
        'action': 'parsed_fields__action',
        'signature': 'parsed_fields__signature',
    }
    for field, lookup in pf_map.items():
        vals = request.query_params.getlist(f'include_{field}')
        for v in vals:
            if v:
                qs = qs.filter(**{lookup: v})
        vals = request.query_params.getlist(f'exclude_{field}')
        for v in vals:
            if v:
                qs = qs.exclude(**{lookup: v})

    dt_from, dt_to = _parse_time_range(request)
    qs = qs.filter(event_time__gte=dt_from, event_time__lte=dt_to)

    total = qs.count()
    offset = (int(page) - 1) * page_size
    events = qs.order_by(ordering)[offset:offset + page_size]

    serializer = LogEventListSerializer(events, many=True)
    return Response({
        'count': total,
        'page': int(page),
        'page_size': page_size,
        'results': serializer.data,
    })


@api_view(['GET'])
@permission_classes([AllowAny])
def event_detail(request, pk):
    try:
        event = LogEventRaw.objects.select_related('source').get(pk=pk)
    except LogEventRaw.DoesNotExist:
        return Response(
            {'error': 'Event not found'},
            status=status.HTTP_404_NOT_FOUND,
        )

    serializer = LogEventDetailSerializer(event)
    return Response(serializer.data)


@api_view(['GET'])
@permission_classes([AllowAny])
def log_statistics(request):
    hours = int(request.query_params.get('hours', 24))
    source_type = request.query_params.get('source_type', '')
    severity = request.query_params.get('severity', '')
    category = request.query_params.get('category', '')
    search = request.query_params.get('q', '')

    cutoff = timezone.now() - timedelta(hours=hours)
    qs = LogEventRaw.objects.filter(event_time__gte=cutoff)

    if source_type:
        qs = qs.filter(source_type=source_type)
    if severity:
        qs = qs.filter(severity=severity)
    if category:
        qs = qs.filter(event_category=category)
    if search:
        qs = qs.filter(Q(message__icontains=search) | Q(host_name__icontains=search) | Q(host_ip__icontains=search))

    severity_dist = list(qs.values('severity').annotate(count=Count('id')).order_by('-count'))
    source_dist = list(qs.values('source_type').annotate(count=Count('id')).order_by('-count'))
    category_dist = list(qs.values('event_category').annotate(count=Count('id')).order_by('-count'))
    top_hosts = list(
        qs.values('host_ip')
        .annotate(count=Count('id'))
        .filter(host_ip__isnull=False)
        .order_by('-count')[:20]
    )

    return Response({
        'total_events': qs.count(),
        'severity_distribution': severity_dist,
        'source_distribution': source_dist,
        'category_distribution': category_dist,
        'top_hosts': top_hosts,
    })


@api_view(['GET'])
@permission_classes([AllowAny])
def suricata_stats(request):
    hours = int(request.query_params.get('hours', 6))

    cutoff = timezone.now() - timedelta(hours=hours)
    qs = LogEventRaw.objects.filter(source_type='suricata', event_time__gte=cutoff)

    # Generic include/exclude filters for top-level fields
    for key in ('severity', 'host_ip', 'host_name', 'event_category'):
        vals = request.query_params.getlist(f'include_{key}')
        for v in vals:
            if v:
                qs = qs.filter(**{key: v})
        vals = request.query_params.getlist(f'exclude_{key}')
        for v in vals:
            if v:
                qs = qs.exclude(**{key: v})

    # Generic parsed_fields include/exclude filters
    pf_map = {
        'src_ip': 'parsed_fields__src_ip',
        'dest_ip': 'parsed_fields__dest_ip',
        'protocol': 'parsed_fields__protocol',
        'action': 'parsed_fields__action',
        'signature': 'parsed_fields__signature',
    }
    for field, lookup in pf_map.items():
        vals = request.query_params.getlist(f'include_{field}')
        for v in vals:
            if v:
                qs = qs.filter(**{lookup: v})
        vals = request.query_params.getlist(f'exclude_{field}')
        for v in vals:
            if v:
                qs = qs.exclude(**{lookup: v})

    total_events = qs.count()

    total_signatures = qs.exclude(parsed_fields={}).exclude(
        **{'parsed_fields__signature': ''}
    ).annotate(
        sig=KeyTextTransform('signature', 'parsed_fields')
    ).values('sig').distinct().count()

    severity_dist = list(qs.values('severity').annotate(count=Count('id')).order_by('-count'))

    event_type_dist = list(qs.exclude(parsed_fields={}).annotate(
        et=KeyTextTransform('event_type', 'parsed_fields')
    ).exclude(et__isnull=True).values('et').annotate(
        count=Count('id')
    ).order_by('-count')[:20])

    proto_dist = list(qs.exclude(parsed_fields={}).annotate(
        proto=KeyTextTransform('protocol', 'parsed_fields')
    ).exclude(proto__isnull=True).exclude(proto='').values('proto').annotate(
        count=Count('id')
    ).order_by('-count')[:20])

    action_dist = list(qs.exclude(parsed_fields={}).annotate(
        act=KeyTextTransform('action', 'parsed_fields')
    ).exclude(act__isnull=True).values('act').annotate(
        count=Count('id')
    ).order_by('-count')[:10])

    top_ports = list(qs.exclude(parsed_fields={}).annotate(
        port=KeyTextTransform('dst_port', 'parsed_fields')
    ).exclude(port__isnull=True).exclude(port='').values('port').annotate(
        count=Count('id')
    ).order_by('-count')[:20])

    top_signatures = list(qs.exclude(parsed_fields={}).annotate(
        sig=KeyTextTransform('signature', 'parsed_fields')
    ).exclude(sig__isnull=True).exclude(sig='').values('sig').annotate(
        count=Count('id')
    ).order_by('-count')[:20])

    classtype_dist = list(qs.exclude(parsed_fields={}).annotate(
        ct=KeyTextTransform('classtype', 'parsed_fields')
    ).exclude(ct__isnull=True).exclude(ct='').values('ct').annotate(
        count=Count('id')
    ).order_by('-count')[:20])

    top_src_ips = list(qs.exclude(parsed_fields={}).annotate(
        ip=KeyTextTransform('src_ip', 'parsed_fields')
    ).exclude(ip__isnull=True).exclude(ip='').values('ip').annotate(
        count=Count('id')
    ).order_by('-count')[:20])

    top_dst_ips = list(qs.exclude(parsed_fields={}).annotate(
        ip=KeyTextTransform('dest_ip', 'parsed_fields')
    ).exclude(ip__isnull=True).exclude(ip='').values('ip').annotate(
        count=Count('id')
    ).order_by('-count')[:20])

    return Response({
        'total_events': total_events,
        'total_signatures': total_signatures,
        'severity_dist': severity_dist,
        'event_type_dist': event_type_dist,
        'proto_dist': proto_dist,
        'action_dist': action_dist,
        'top_ports': top_ports,
        'top_signatures': top_signatures,
        'classtype_dist': classtype_dist,
        'top_src_ips': top_src_ips,
        'top_dst_ips': top_dst_ips,
    })


@api_view(['GET'])
@permission_classes([AllowAny])
def event_histogram(request):
    bucket_minutes = int(request.query_params.get('bucket_minutes', 60))
    source_type = request.query_params.get('source_type', '')
    severity = request.query_params.get('severity', '')
    category = request.query_params.get('category', '')
    search = request.query_params.get('q', '')

    dt_from, dt_to = _parse_time_range(request)
    qs = LogEventRaw.objects.filter(event_time__gte=dt_from, event_time__lte=dt_to)

    if source_type:
        qs = qs.filter(source_type=source_type)

    # Apply include/exclude filters (same logic as event_list)
    for key in ('severity', 'host_ip', 'host_name', 'event_category'):
        vals = request.query_params.getlist(f'include_{key}')
        for v in vals:
            if v:
                qs = qs.filter(**{key: v})
        vals = request.query_params.getlist(f'exclude_{key}')
        for v in vals:
            if v:
                qs = qs.exclude(**{key: v})

    if severity and 'include_severity' not in request.query_params:
        qs = qs.filter(severity=severity)
    if category:
        qs = qs.filter(event_category=category)
    if search:
        qs = qs.filter(Q(message__icontains=search) | Q(host_name__icontains=search) | Q(host_ip__icontains=search))

    # Generic parsed_fields include/exclude filters
    pf_map = {
        'src_ip': 'parsed_fields__src_ip',
        'dest_ip': 'parsed_fields__dest_ip',
        'protocol': 'parsed_fields__protocol',
        'action': 'parsed_fields__action',
        'signature': 'parsed_fields__signature',
    }
    for field, lookup in pf_map.items():
        vals = request.query_params.getlist(f'include_{field}')
        for v in vals:
            if v:
                qs = qs.filter(**{lookup: v})
        vals = request.query_params.getlist(f'exclude_{field}')
        for v in vals:
            if v:
                qs = qs.exclude(**{lookup: v})

    bucket_seconds = bucket_minutes * 60
    qs_agg = qs.annotate(
        time_bucket=RawSQL(
            "to_timestamp(floor(extract(epoch from event_time) / %s) * %s)",
            [bucket_seconds, bucket_seconds],
        )
    ).values('time_bucket').annotate(count=Count('id')).order_by('time_bucket')

    return Response({
        'timeline': [{'time': str(r['time_bucket']), 'count': r['count']} for r in qs_agg],
        'total': qs.count(),
    })


@api_view(['GET'])
@permission_classes([AllowAny])
def retention_list(request):
    policies = LogRetentionPolicy.objects.all()
    serializer = LogRetentionPolicySerializer(policies, many=True)
    return Response(serializer.data)


@api_view(['POST'])
@permission_classes([AllowAny])
def retention_cleanup(request):
    cleaned = {}
    policies = LogRetentionPolicy.objects.filter(auto_delete=True)

    for policy in policies:
        cutoff = timezone.now() - timedelta(days=policy.retention_days)
        result = LogEventRaw.objects.filter(
            source_type=policy.source_type,
            event_time__lt=cutoff,
        ).delete()
        cleaned[policy.source_type] = result[0]
        policy.last_cleanup_at = timezone.now()
        policy.save(update_fields=['last_cleanup_at'])

    return Response({
        'status': 'ok',
        'cleaned': cleaned,
    })


@api_view(['GET'])
@permission_classes([AllowAny])
def storage_dashboard(request):
    now = timezone.now()

    total_events = LogEventRaw.objects.count()
    total_sources = LogSource.objects.count()
    active_sources = LogSource.objects.filter(enabled=True).count()

    oldest_event = LogEventRaw.objects.order_by('event_time').values_list('event_time', flat=True).first()
    newest_event = LogEventRaw.objects.order_by('-event_time').values_list('event_time', flat=True).first()

    events_by_source = list(
        LogEventRaw.objects.values('source_type')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    events_by_severity = list(
        LogEventRaw.objects.values('severity')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    events_last_7d = list(
        LogEventRaw.objects.filter(event_time__gte=now - timedelta(days=7))
        .annotate(day=RawSQL("date_trunc('day', event_time)", []))
        .values('day')
        .annotate(count=Count('id'))
        .order_by('day')
    )

    retention_policies = list(LogRetentionPolicy.objects.values(
        'source_type', 'retention_days', 'auto_delete', 'last_cleanup_at'
    ))
    for p in retention_policies:
        if p['last_cleanup_at']:
            p['last_cleanup_at'] = str(p['last_cleanup_at'])
        oldest_cutoff = now - timedelta(days=p['retention_days'])
        p['oldest_allowed'] = str(oldest_cutoff)

    table_sizes = []
    with connection.cursor() as cur:
        cur.execute("""
            SELECT
                relname AS table_name,
                pg_size_pretty(pg_total_relation_size(relid)) AS total_size,
                pg_size_pretty(pg_relation_size(relid)) AS table_size,
                pg_size_pretty(pg_total_relation_size(relid) - pg_relation_size(relid)) AS index_size,
                pg_stat_get_live_tuples(relid) AS live_rows,
                pg_stat_get_dead_tuples(relid) AS dead_rows
            FROM pg_stat_user_tables
            WHERE schemaname = 'public'
            ORDER BY pg_total_relation_size(relid) DESC
        """)
        for row in cur.fetchall():
            table_sizes.append({
                'table_name': row[0],
                'total_size': row[1],
                'table_size': row[2],
                'index_size': row[3],
                'live_rows': row[4],
                'dead_rows': row[5],
            })

    db_size_pretty = 'unknown'
    with connection.cursor() as cur:
        cur.execute("SELECT pg_size_pretty(pg_database_size(current_database()))")
        db_size_pretty = cur.fetchone()[0]

    disk_info = {}
    try:
        st = os.statvfs('/')
        total_bytes = st.f_blocks * st.f_frsize
        free_bytes = st.f_bavail * st.f_frsize
        used_bytes = total_bytes - free_bytes
        disk_info = {
            'total': f'{total_bytes / (1024**3):.1f} GB',
            'used': f'{used_bytes / (1024**3):.1f} GB',
            'free': f'{free_bytes / (1024**3):.1f} GB',
            'percent': round((used_bytes / total_bytes) * 100, 1) if total_bytes else 0,
        }
    except OSError:
        pass

    return Response({
        'total_events': total_events,
        'total_sources': total_sources,
        'active_sources': active_sources,
        'oldest_event': str(oldest_event) if oldest_event else None,
        'newest_event': str(newest_event) if newest_event else None,
        'events_by_source': events_by_source,
        'events_by_severity': events_by_severity,
        'events_last_7d': [{'day': str(e['day']), 'count': e['count']} for e in events_last_7d],
        'retention_policies': retention_policies,
        'table_sizes': table_sizes,
        'db_size': db_size_pretty,
        'disk': disk_info,
    })
