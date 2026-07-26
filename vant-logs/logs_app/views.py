import json
import logging
from datetime import datetime, timedelta

from django.db import connection
from django.db.models import Count, Q
from django.db.models.expressions import RawSQL
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
def event_list(request):
    qs = LogEventRaw.objects.select_related('source').all()

    source_type = request.query_params.get('source_type')
    severity = request.query_params.get('severity')
    host_ip = request.query_params.get('host_ip')
    category = request.query_params.get('category')
    search = request.query_params.get('q')
    hours = request.query_params.get('hours')
    ordering = request.query_params.get('ordering', '-event_time')
    page = request.query_params.get('page', 1)
    page_size = min(int(request.query_params.get('page_size', 50)), 200)

    if source_type:
        qs = qs.filter(source_type=source_type)
    if severity:
        qs = qs.filter(severity=severity)
    if host_ip:
        qs = qs.filter(host_ip=host_ip)
    if category:
        qs = qs.filter(event_category=category)
    if search:
        qs = qs.filter(Q(message__icontains=search) | Q(host_name__icontains=search))
    if hours:
        try:
            cutoff = timezone.now() - timedelta(hours=int(hours))
            qs = qs.filter(event_time__gte=cutoff)
        except ValueError:
            pass

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
def event_histogram(request):
    hours = int(request.query_params.get('hours', 24))
    bucket_minutes = int(request.query_params.get('bucket_minutes', 60))
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
