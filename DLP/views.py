import logging
from datetime import datetime, timedelta, timezone

from django.db.models import Count, Q
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework.response import Response

from .models import DlpPolicy, DlpRule, DlpIncident, DlpScanSummary
from .serializers import (
    DlpPolicySerializer, DlpRuleSerializer,
    DlpIncidentListSerializer, DlpIncidentDetailSerializer,
    DlpIncidentIngestSerializer, DlpScanSummarySerializer,
    DlpAgentConfigSerializer,
)

logger = logging.getLogger(__name__)


class DlpPolicyViewSet(viewsets.ModelViewSet):
    queryset = DlpPolicy.objects.all()
    serializer_class = DlpPolicySerializer
    lookup_field = 'code'

    def get_queryset(self):
        qs = super().get_queryset()
        enabled = self.request.query_params.get('enabled')
        if enabled is not None:
            qs = qs.filter(enabled=enabled.lower() == 'true')
        return qs

    @action(detail=True, methods=['get'])
    def rules(self, request, code=None):
        policy = self.get_object()
        rules = policy.rules.filter(enabled=True)
        serializer = DlpRuleSerializer(rules, many=True)
        return Response(serializer.data)


class DlpRuleViewSet(viewsets.ModelViewSet):
    queryset = DlpRule.objects.all()
    serializer_class = DlpRuleSerializer
    permission_classes = [IsAdminUser]


class DlpIncidentViewSet(viewsets.ModelViewSet):
    http_method_names = ['get', 'patch', 'head', 'options']
    lookup_field = 'pk'

    def get_queryset(self):
        qs = DlpIncident.objects.all()
        severity = self.request.query_params.get('severity')
        status_filter = self.request.query_params.get('status')
        classification = self.request.query_params.get('classification')
        agent_id = self.request.query_params.get('agent_id')
        channel = self.request.query_params.get('channel')
        search = self.request.query_params.get('q')
        hours = self.request.query_params.get('hours')

        if severity:
            qs = qs.filter(severity=severity)
        if status_filter:
            qs = qs.filter(status=status_filter)
        if classification:
            qs = qs.filter(classification=classification)
        if agent_id:
            qs = qs.filter(remote_agent_id=agent_id)
        if channel:
            qs = qs.filter(channel=channel)
        if search:
            qs = qs.filter(Q(file_name__icontains=search) | Q(file_path__icontains=search) | Q(actor__icontains=search))
        if hours:
            try:
                cutoff = timezone.now().replace(tzinfo=None) - timedelta(hours=int(hours))
                qs = qs.filter(detected_at__gte=cutoff)
            except (ValueError, TypeError):
                pass
        return qs.order_by('-detected_at')

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return DlpIncidentDetailSerializer
        return DlpIncidentListSerializer

    @action(detail=True, methods=['patch'])
    def acknowledge(self, request, pk=None):
        incident = self.get_object()
        incident.status = 'acknowledged'
        incident.acknowledged_at = timezone.now()
        incident.acknowledged_by = request.user.username if request.user.is_authenticated else 'api'
        incident.save(update_fields=['status', 'acknowledged_at', 'acknowledged_by'])
        return Response({'status': 'acknowledged', 'id': incident.id})

    @action(detail=True, methods=['patch'])
    def resolve(self, request, pk=None):
        incident = self.get_object()
        incident.status = request.data.get('status', 'resolved')
        incident.resolved_at = timezone.now()
        incident.resolved_by = request.user.username if request.user.is_authenticated else 'api'
        incident.resolution_notes = request.data.get('notes', '')
        incident.save(update_fields=['status', 'resolved_at', 'resolved_by', 'resolution_notes'])
        return Response({'status': incident.status, 'id': incident.id})


@api_view(['GET'])
@permission_classes([AllowAny])
def dlp_agent_config(request):
    policies = DlpPolicy.objects.filter(enabled=True).prefetch_related('rules')
    serializer = DlpAgentConfigSerializer({'policies': policies})
    return Response(serializer.data)


@api_view(['POST'])
@permission_classes([AllowAny])
def ingest_dlp_threats(request):
    serializer = DlpIncidentIngestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    data = serializer.validated_data
    agent_id = data['agent_id']
    incidents_data = data['incidents']

    if not incidents_data:
        return Response({'status': 'ok', 'ingested': 0})

    host_name = incidents_data[0].get('host_name', '')
    created_count = 0
    skipped_count = 0

    for inc_data in incidents_data:
        fingerprint = inc_data.get('fingerprint', '')
        if not fingerprint:
            skipped_count += 1
            continue

        try:
            detected_at_str = inc_data.get('detected_at', '')
            if detected_at_str:
                detected_at = datetime.fromisoformat(detected_at_str.replace('Z', '+00:00'))
                if detected_at.tzinfo:
                    detected_at = detected_at.replace(tzinfo=None)
            else:
                detected_at = timezone.now().replace(tzinfo=None)
        except (ValueError, TypeError):
            detected_at = timezone.now().replace(tzinfo=None)

        incident, created = DlpIncident.objects.update_or_create(
            fingerprint=fingerprint,
            defaults={
                'remote_agent_id': agent_id,
                'host_name': host_name,
                'policy_code': inc_data.get('policy_code', ''),
                'rule_name': inc_data.get('rule_name', ''),
                'classification': inc_data.get('classification', ''),
                'severity': inc_data.get('severity', 'high'),
                'status': inc_data.get('status', 'open'),
                'file_name': inc_data.get('file_name', ''),
                'file_path': inc_data.get('file_path', ''),
                'file_hash': inc_data.get('file_hash', ''),
                'actor': inc_data.get('actor', ''),
                'channel': inc_data.get('channel', 'filesystem'),
                'summary': inc_data.get('summary', ''),
                'matched_keywords': inc_data.get('matched_keywords', []),
                'metadata': inc_data.get('metadata', {}),
                'detected_at': detected_at,
            },
        )
        if created:
            created_count += 1

    logger.info('DLP ingest: agent=%s created=%s skipped=%s total=%s', agent_id, created_count, skipped_count, len(incidents_data))

    return Response({
        'status': 'ok',
        'ingested': created_count,
        'skipped': skipped_count,
        'total_received': len(incidents_data),
    }, status=status.HTTP_201_CREATED)


class DlpScanSummaryViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = DlpScanSummary.objects.all()
    serializer_class = DlpScanSummarySerializer

    def get_queryset(self):
        qs = super().get_queryset()
        agent_id = self.request.query_params.get('agent_id')
        if agent_id:
            qs = qs.filter(remote_agent_id=agent_id)
        return qs.order_by('-started_at')


@api_view(['GET'])
@permission_classes([IsAdminUser])
def dlp_statistics(request):
    hours = int(request.query_params.get('hours', 24))
    cutoff = timezone.now().replace(tzinfo=None) - timedelta(hours=hours)

    qs = DlpIncident.objects.filter(detected_at__gte=cutoff)

    severity_dist = list(qs.values('severity').annotate(count=Count('id')).order_by('-count'))
    classification_dist = list(qs.values('classification').annotate(count=Count('id')).order_by('-count'))
    status_dist = list(qs.values('status').annotate(count=Count('id')).order_by('-count'))
    channel_dist = list(qs.values('channel').annotate(count=Count('id')).order_by('-count'))
    top_agents = list(qs.values('remote_agent_id', 'host_name').annotate(count=Count('id')).order_by('-count')[:10])
    top_files = list(qs.values('file_name').annotate(count=Count('id')).order_by('-count')[:10])

    timeline = list(qs.extra(
        select={'time_bucket': "date_trunc('hour', detected_at)"}
    ).values('time_bucket').annotate(count=Count('id')).order_by('time_bucket'))

    return Response({
        'total_incidents': qs.count(),
        'severity_distribution': severity_dist,
        'classification_distribution': classification_dist,
        'status_distribution': status_dist,
        'channel_distribution': channel_dist,
        'top_agents': top_agents,
        'top_files': top_files,
        'timeline': [{'time': str(r['time_bucket']), 'count': r['count']} for r in timeline],
    })
