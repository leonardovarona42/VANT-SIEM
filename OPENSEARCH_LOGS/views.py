import json
import logging
from datetime import datetime, timedelta
from django.db.models import Count, Q
from django.utils import timezone
from django.http import JsonResponse
from rest_framework import generics, status, viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from .models import LogSource, LogEvent, LogRetentionPolicy
from .serializers import (
    LogSourceSerializer, LogEventListSerializer, LogEventDetailSerializer,
    LogIngestSerializer, LogBulkIngestSerializer, LogRetentionPolicySerializer,
)
from .parsers import get_parser

logger = logging.getLogger(__name__)


@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    try:
        from django.db import connection
        connection.ensure_connection()
        db_ok = True
    except Exception:
        db_ok = False
    return Response({
        'status': 'healthy' if db_ok else 'degraded',
        'service': 'opensearch_logs',
        'database': 'connected' if db_ok else 'disconnected',
        'timestamp': timezone.now().isoformat(),
    })


class LogSourceViewSet(viewsets.ModelViewSet):
    queryset = LogSource.objects.all()
    serializer_class = LogSourceSerializer
    lookup_field = 'source_id'
    permission_classes = [IsAuthenticated]


class LogEventListView(generics.ListAPIView):
    serializer_class = LogEventListSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = LogEvent.objects.all()
        source_type = self.request.query_params.get('source_type')
        severity = self.request.query_params.get('severity')
        host_ip = self.request.query_params.get('host_ip')
        category = self.request.query_params.get('category')
        search = self.request.query_params.get('q')
        hours = self.request.query_params.get('hours')
        ordering = self.request.query_params.get('ordering', '-event_time')

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
        return qs.order_by(ordering)


class LogEventDetailView(generics.RetrieveAPIView):
    queryset = LogEvent.objects.all()
    serializer_class = LogEventDetailSerializer
    lookup_field = 'pk'
    permission_classes = [IsAuthenticated]


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def ingest_log(request):
    serializer = LogIngestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    data = serializer.validated_data
    source_id = data['source_id']
    raw_message = data['raw_message']

    try:
        source = LogSource.objects.get(source_id=source_id)
        source.touch()
        source_type = data.get('source_type') or source.source_type
    except LogSource.DoesNotExist:
        source_type = data.get('source_type', 'generic_syslog')
        source = LogSource(
            source_id=source_id,
            source_type=source_type,
            host_ip=request.META.get('REMOTE_ADDR'),
            protocol='http_post',
        )
        source.save()
        logger.info(f'Auto-registered source: {source_id} ({source_type})')

    parser = get_parser(source_type)
    parsed = parser.parse(raw_message)

    event_time = data.get('event_time')
    if event_time is None:
        event_time = parsed.get('event_time_dt') or timezone.now()

    event = LogEvent.create_from_parsed(source, parsed, raw_message, event_time)
    event.save()

    if parsed.get('severity') in ('critical', 'high'):
        try:
            from CORE.arkangel import ServiceBus, LOG_ALERT_TRIGGERED
            bus = ServiceBus()
            bus.publish(LOG_ALERT_TRIGGERED, {
                'source_id': source_id,
                'source_type': source_type,
                'severity': parsed['severity'],
                'category': parsed['event_category'],
                'host_ip': parsed['host_ip'],
                'event_id': event.id,
            })
        except Exception as e:
            logger.warning(f'Failed to publish alert to service bus: {e}')

    return Response({
        'status': 'ok',
        'event_id': event.id,
        'severity': event.severity,
        'category': event.event_category,
    }, status=status.HTTP_201_CREATED)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def ingest_bulk(request):
    data = request.data

    if 'events' in data and 'source_id' not in data:
        events = data.get('events', [])
        if not events:
            return Response({'status': 'ok', 'ingested': 0})

        source_type = events[0].get('source_type', 'generic')
        source_id = f"agent-{source_type}"

        try:
            source = LogSource.objects.get(source_id=source_id)
        except LogSource.DoesNotExist:
            source = LogSource.objects.create(
                source_id=source_id,
                source_type=source_type,
                host_name=events[0].get('host_name', ''),
                enabled=True,
            )

        source.touch()
        events_to_create = []
        alerts = []
        now = timezone.now()

        for event in events:
            raw = json.dumps(event) if isinstance(event, dict) else str(event)
            event_time_str = event.get('event_time')
            if event_time_str and isinstance(event_time_str, str):
                try:
                    event_time = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
                except ValueError:
                    event_time = now
            else:
                event_time = now

            parsed = {
                'event_category': event.get('event_category', 'generic'),
                'severity': event.get('severity', 'info'),
                'host_ip': event.get('host_ip', ''),
                'host_name': event.get('host_name', ''),
                'message': event.get('message', ''),
            }

            log_event = LogEvent(
                source=source,
                source_type=source_type,
                raw_payload=json.loads(raw) if isinstance(raw, str) else raw,
                event_time=event_time,
                event_category=parsed['event_category'],
                severity=parsed['severity'],
                host_ip=parsed['host_ip'],
                host_name=parsed['host_name'],
                message=parsed['message'][:512],
                tags=event.get('tags', []),
            )
            events_to_create.append(log_event)

            if parsed['severity'] in ('critical', 'high'):
                alerts.append({
                    'source_type': source_type,
                    'severity': parsed['severity'],
                    'category': parsed['event_category'],
                    'host_ip': parsed['host_ip'],
                })

        created = LogEvent.bulk_create_events(events_to_create)

        if alerts:
            try:
                from CORE.arkangel import ServiceBus, LOG_ALERT_TRIGGERED
                bus = ServiceBus()
                for alert in alerts:
                    bus.publish(LOG_ALERT_TRIGGERED, alert)
            except Exception as e:
                logger.warning(f'Failed to publish alerts: {e}')

        return Response({
            'status': 'ok',
            'ingested': created,
            'alerts_triggered': len(alerts),
        }, status=status.HTTP_201_CREATED)

    serializer = LogBulkIngestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    data = serializer.validated_data
    source_id = data['source_id']
    logs = data['logs']

    try:
        source = LogSource.objects.get(source_id=source_id)
        source.touch()
        source_type = source.source_type
    except LogSource.DoesNotExist:
        return Response({'error': f'Source {source_id} not found'}, status=status.HTTP_404_NOT_FOUND)

    parser = get_parser(source_type)
    events_to_create = []
    alerts = []
    now = timezone.now()

    for log_entry in logs:
        raw = json.dumps(log_entry) if isinstance(log_entry, dict) else str(log_entry)
        parsed = parser.parse(raw)
        event_time_str = log_entry.get('event_time') if isinstance(log_entry, dict) else None
        if event_time_str and isinstance(event_time_str, str):
            try:
                event_time = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
            except ValueError:
                event_time = now
        else:
            event_time = now

        event = LogEvent.create_from_parsed(source, parsed, raw, event_time)
        events_to_create.append(event)
        if parsed.get('severity') in ('critical', 'high'):
            alerts.append({
                'source_type': source_type,
                'severity': parsed['severity'],
                'category': parsed['event_category'],
                'host_ip': parsed['host_ip'],
            })

    created = LogEvent.bulk_create_events(events_to_create)

    if alerts:
        try:
            from CORE.arkangel import ServiceBus, LOG_ALERT_TRIGGERED
            bus = ServiceBus()
            for alert in alerts:
                bus.publish(LOG_ALERT_TRIGGERED, alert)
        except Exception as e:
            logger.warning(f'Failed to publish alerts: {e}')

    return Response({
        'status': 'ok',
        'ingested': created,
        'alerts_triggered': len(alerts),
    }, status=status.HTTP_201_CREATED)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def ingest_syslog(request):
    raw = request.body.decode('utf-8', errors='replace').strip()
    if not raw:
        return Response({'error': 'Empty syslog message'}, status=status.HTTP_400_BAD_REQUEST)

    source_ip = request.META.get('REMOTE_ADDR')

    from .parsers import GenericSyslogParser
    parser = GenericSyslogParser()
    parsed = parser.parse(raw)

    hostname = parsed.get('hostname') or source_ip
    source_id = f'syslog-{hostname}'

    try:
        source = LogSource.objects.get(source_id=source_id)
        source.touch()
    except LogSource.DoesNotExist:
        source = LogSource(
            source_id=source_id,
            source_type='generic_syslog',
            vendor='Unknown',
            host_name=hostname,
            host_ip=source_ip,
            protocol='syslog',
        )
        source.save()

    event = LogEvent.create_from_parsed(source, parsed, raw)
    event.save()

    return Response({'status': 'ok', 'event_id': event.id}, status=status.HTTP_201_CREATED)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def log_statistics(request):
    hours = int(request.query_params.get('hours', 24))
    cutoff = timezone.now() - timedelta(hours=hours)

    qs = LogEvent.objects.filter(event_time__gte=cutoff)

    severity_dist = list(qs.values('severity').annotate(count=Count('id')).order_by('-count'))
    source_dist = list(qs.values('source_type').annotate(count=Count('id')).order_by('-count'))
    category_dist = list(qs.values('event_category').annotate(count=Count('id')).order_by('-count'))

    timeline = list(qs.extra(
        select={'time_bucket': "date_trunc('hour', event_time)"}
    ).values('time_bucket').annotate(count=Count('id')).order_by('time_bucket'))

    top_hosts = list(qs.values('host_ip').annotate(count=Count('id')).filter(host_ip__isnull=False).order_by('-count')[:20])

    return Response({
        'total_events': qs.count(),
        'severity_distribution': severity_dist,
        'source_distribution': source_dist,
        'category_distribution': category_dist,
        'timeline': [{'time': str(r['time_bucket']), 'count': r['count']} for r in timeline],
        'top_hosts': top_hosts,
    })


class LogRetentionPolicyViewSet(viewsets.ModelViewSet):
    queryset = LogRetentionPolicy.objects.all()
    serializer_class = LogRetentionPolicySerializer
    lookup_field = 'source_type'
    permission_classes = [IsAuthenticated]
