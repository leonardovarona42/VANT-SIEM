import json
import logging
from datetime import datetime, timedelta
from django.db.models import Count, Q
from django.db.models.functions import TruncDate
from django.utils import timezone
from django.http import JsonResponse
from rest_framework import status, viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .models import Agent, HardwareInventory, SoftwareInventory, AgentCommand
from .serializers import (
    AgentListSerializer, AgentDetailSerializer, AgentRegisterSerializer,
    HardwareInventorySerializer, SoftwareInventorySerializer,
    AgentCommandSerializer, AgentCommandCreateSerializer,
    HeartbeatSerializer, InventorySubmitSerializer, AgentStatsSerializer,
    AgentConfigPushSerializer,
)

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
    total = Agent.objects.count()
    online = Agent.objects.filter(status='online').count()
    return Response({
        'status': 'healthy' if db_ok else 'degraded',
        'service': 'inventory',
        'database': 'connected' if db_ok else 'disconnected',
        'total_agents': total,
        'online_agents': online,
        'timestamp': timezone.now().isoformat(),
    })


@api_view(['GET'])
def agent_stats(request):
    now = timezone.now()
    stats = {
        'total_agents': Agent.objects.count(),
        'online': Agent.objects.filter(status='online').count(),
        'offline': Agent.objects.filter(status='offline').count(),
        'pending': Agent.objects.filter(status='pending').count(),
        'error': Agent.objects.filter(status='error').count(),
        'disabled': Agent.objects.filter(status='disabled').count(),
        'os_distribution': dict(
            Agent.objects.values('os_type').annotate(c=Count('agent_id')).order_by('-c').values_list('os_type', 'c')
        ),
        'agents_by_day': dict(
            Agent.objects
            .filter(registered_at__gte=now - timedelta(days=30))
            .annotate(day=TruncDate('registered_at'))
            .values('day')
        .annotate(count=Count('agent_id'))
        .order_by('day')
        .values_list('day', 'count')
        ),
    }
    return Response(stats)


@api_view(['POST'])
@permission_classes([AllowAny])
def register_agent(request):
    serializer = AgentRegisterSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    data = serializer.validated_data
    hostname = data['hostname']
    mac = data.get('mac_address', '')
    machine_name = data.get('machine_name', hostname)

    # Deduplicate by machine_name first, then MAC
    if machine_name:
        agent = Agent.objects.filter(machine_name=machine_name).first()
    elif mac:
        agent = Agent.objects.filter(mac_address=mac).first()
    else:
        agent = None

    created = False
    if agent is None:
        agent = Agent.objects.create(
            hostname=hostname,
            machine_name=machine_name,
            os_type=data.get('os_type', 'other'),
            os_version=data.get('os_version', ''),
            os_arch=data.get('os_arch', 'x86_64'),
            agent_version=data.get('agent_version', '1.0.0'),
            ip_address=data.get('ip_address'),
            mac_address=mac,
            domain=data.get('domain', ''),
            status='online',
            tags=data.get('tags', []),
        )
        created = True

    if not created:
        agent.hostname = hostname
        agent.os_type = data.get('os_type', agent.os_type)
        agent.os_version = data.get('os_version', agent.os_version)
        agent.agent_version = data.get('agent_version', agent.agent_version)
        agent.ip_address = data.get('ip_address', agent.ip_address)
        if mac:
            agent.mac_address = mac
        agent.domain = data.get('domain', agent.domain)
        if agent.status in ('offline', 'pending'):
            agent.status = 'online'
        agent.heartbeat()
        agent.save(update_fields=['hostname', 'os_type', 'os_version', 'agent_version', 'ip_address', 'mac_address', 'domain', 'status'])

    return Response({
        'agent_id': str(agent.agent_id),
        'hostname': agent.hostname,
        'status': agent.status,
        'created': created,
    }, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([AllowAny])
def heartbeat(request):
    serializer = HeartbeatSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    agent_id = serializer.validated_data['agent_id']
    try:
        agent = Agent.objects.get(agent_id=agent_id)
    except Agent.DoesNotExist:
        return Response({'error': 'Agent not found'}, status=status.HTTP_404_NOT_FOUND)

    agent.heartbeat()
    if serializer.validated_data.get('ip_address'):
        agent.ip_address = serializer.validated_data['ip_address']
        agent.save(update_fields=['ip_address', 'updated_at'])

    pending_commands = AgentCommand.objects.filter(agent=agent, status__in=['pending', 'sent'])
    commands_data = AgentCommandSerializer(pending_commands, many=True).data

    pending_commands.update(status='sent', sent_at=timezone.now())

    return Response({
        'status': agent.status,
        'commands': commands_data,
        'timestamp': timezone.now().isoformat(),
    })


@api_view(['POST'])
@permission_classes([AllowAny])
def submit_inventory(request):
    serializer = InventorySubmitSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    agent_id = serializer.validated_data['agent_id']
    try:
        agent = Agent.objects.get(agent_id=agent_id)
    except Agent.DoesNotExist:
        return Response({'error': 'Agent not found'}, status=status.HTTP_404_NOT_FOUND)

    hw_data = serializer.validated_data['hardware']
    sw_data = serializer.validated_data.get('software', [])

    hw, _ = HardwareInventory.objects.update_or_create(
        agent=agent,
        defaults={
            'cpu_model': hw_data.get('cpu_model', ''),
            'cpu_cores': hw_data.get('cpu_cores', 0),
            'cpu_threads': hw_data.get('cpu_threads', 0),
            'cpu_speed_ghz': hw_data.get('cpu_speed_ghz', 0),
            'ram_total_gb': hw_data.get('ram_total_gb', 0),
            'ram_slots_used': hw_data.get('ram_slots_used', 0),
            'ram_slots_total': hw_data.get('ram_slots_total', 0),
            'motherboard_model': hw_data.get('motherboard_model', ''),
            'motherboard_manufacturer': hw_data.get('motherboard_manufacturer', ''),
            'bios_version': hw_data.get('bios_version', ''),
            'gpu_models': hw_data.get('gpu_models', []),
            'disks': hw_data.get('disks', []),
            'network_interfaces': hw_data.get('network_interfaces', []),
            'serial_number': hw_data.get('serial_number', ''),
            'manufacturer': hw_data.get('manufacturer', ''),
            'product_name': hw_data.get('product_name', ''),
        },
    )

    if sw_data:
        agent.software.all().delete()
        sw_objects = []
        for sw in sw_data:
            sw_objects.append(SoftwareInventory(
                agent=agent,
                name=sw.get('name', ''),
                version=sw.get('version', ''),
                publisher=sw.get('publisher', ''),
                install_date=sw.get('install_date'),
                install_location=sw.get('install_location', ''),
                software_type=sw.get('software_type', 'application'),
                size_mb=sw.get('size_mb', 0),
                is_system=sw.get('is_system', False),
            ))
        SoftwareInventory.objects.bulk_create(sw_objects, batch_size=500)

    agent.last_inventory_at = timezone.now()
    agent.save(update_fields=['last_inventory_at', 'updated_at'])

    return Response({
        'status': 'ok',
        'hardware_updated': True,
        'software_count': len(sw_data),
        'timestamp': timezone.now().isoformat(),
    })


@api_view(['POST'])
@permission_classes([AllowAny])
def command_result(request):
    command_id = request.data.get('command_id')
    result_status = request.data.get('status')
    result_data = request.data.get('result', {})
    error = request.data.get('error', '')

    try:
        cmd = AgentCommand.objects.get(command_id=command_id)
    except AgentCommand.DoesNotExist:
        return Response({'error': 'Command not found'}, status=status.HTTP_404_NOT_FOUND)

    if result_status == 'completed':
        cmd.mark_completed(result=result_data)
    elif result_status == 'failed':
        cmd.mark_failed(error=error)
    else:
        cmd.status = result_status
        cmd.save(update_fields=['status'])

    return Response({'status': 'ok'})


class AgentViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Agent.objects.all()
    lookup_field = 'agent_id'

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return AgentDetailSerializer
        return AgentListSerializer

    def list(self, request, *args, **kwargs):
        qs = self.get_queryset()
        status_filter = request.query_params.get('status')
        os_filter = request.query_params.get('os_type')
        search = request.query_params.get('search')

        if status_filter:
            qs = qs.filter(status=status_filter)
        if os_filter:
            qs = qs.filter(os_type=os_filter)
        if search:
            qs = qs.filter(Q(hostname__icontains=search) | Q(ip_address__icontains=search) | Q(machine_name__icontains=search))

        page = self.paginate_queryset(qs)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(qs, many=True)
        return Response(serializer.data)


class SoftwareViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = SoftwareInventory.objects.select_related('agent')
    serializer_class = SoftwareInventorySerializer

    def list(self, request, *args, **kwargs):
        qs = self.get_queryset()
        agent_id = request.query_params.get('agent_id')
        search = request.query_params.get('search')

        if agent_id:
            qs = qs.filter(agent_id=agent_id)
        if search:
            qs = qs.filter(Q(name__icontains=search) | Q(publisher__icontains=search))

        page = self.paginate_queryset(qs)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(qs, many=True)
        return Response(serializer.data)


class AgentCommandViewSet(viewsets.ModelViewSet):
    queryset = AgentCommand.objects.select_related('agent')
    serializer_class = AgentCommandSerializer

    def create(self, request, *args, **kwargs):
        agent_id = request.data.get('agent_id')
        serializer = AgentCommandCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        try:
            agent = Agent.objects.get(agent_id=agent_id)
        except Agent.DoesNotExist:
            return Response({'error': 'Agent not found'}, status=status.HTTP_404_NOT_FOUND)

        cmd = AgentCommand.objects.create(
            agent=agent,
            command_type=serializer.validated_data['command_type'],
            payload=serializer.validated_data.get('payload', {}),
        )

        return Response(AgentCommandSerializer(cmd).data, status=status.HTTP_201_CREATED)


DEFAULT_CONFIG = {
    'inventory': {'enabled': True, 'interval': 300},
    'collectors': {
        'snort': {'enabled': False, 'path': ''},
        'suricata': {'enabled': False, 'path': ''},
        'windows_eventlog': {'enabled': False, 'channels': ['Security', 'System']},
        'postgres': {'enabled': False, 'path': ''},
        'file_logs': {'enabled': False, 'items': []},
    },
    'dlp': {
        'enabled': False,
        'scan_paths': [],
        'scan_extensions': ['.docx', '.xlsx', '.pdf', '.txt'],
        'keywords': ['clasificado', 'secreto', 'restringido'],
    },
    'agent': {
        'check_interval': 60,
        'heartbeat_interval': 300,
        'log_level': 'INFO',
    },
}


@api_view(['PUT'])
def push_config(request, agent_id):
    serializer = AgentConfigPushSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    try:
        agent = Agent.objects.get(agent_id=agent_id)
    except Agent.DoesNotExist:
        return Response({'error': 'Agent not found'}, status=status.HTTP_404_NOT_FOUND)

    config_data = serializer.validated_data['config']

    cmd = AgentCommand.objects.create(
        agent=agent,
        command_type='push_config',
        payload={
            'config': config_data,
            'config_hash': hash(str(config_data)),
        },
    )

    return Response({
        'status': 'ok',
        'command_id': str(cmd.command_id),
        'message': 'Config command queued for agent',
    })


@api_view(['GET'])
def get_agent_config(request, agent_id):
    try:
        agent = Agent.objects.get(agent_id=agent_id)
    except Agent.DoesNotExist:
        return Response({'error': 'Agent not found'}, status=status.HTTP_404_NOT_FOUND)

    pending_config_cmds = AgentCommand.objects.filter(
        agent=agent, command_type='push_config', status='pending'
    ).order_by('-created_at')

    return Response({
        'pending_config_commands': AgentCommandSerializer(pending_config_cmds, many=True).data,
        'config_template': DEFAULT_CONFIG,
    })


@api_view(['GET'])
def config_templates(request):
    return Response({
        'defaults': DEFAULT_CONFIG,
        'module_definitions': {
            'inventory': {
                'name': 'Hardware & Software Inventory',
                'enabled_by_default': True,
                'options': {
                    'enabled': {'type': 'boolean', 'default': True},
                    'interval': {'type': 'integer', 'default': 300, 'min': 60, 'max': 86400},
                },
            },
            'collectors': {
                'name': 'Log Collectors',
                'enabled_by_default': False,
                'submodules': {
                    'snort': {'name': 'Snort IDS Logs'},
                    'suricata': {'name': 'Suricata IDS Logs'},
                    'windows_eventlog': {'name': 'Windows Event Log', 'channels': ['Security', 'System', 'Application']},
                    'postgres': {'name': 'PostgreSQL Logs'},
                    'file_logs': {'name': 'File Log Collector'},
                },
            },
            'dlp': {
                'name': 'Data Loss Prevention (Aegis)',
                'enabled_by_default': False,
                'options': {
                    'enabled': {'type': 'boolean', 'default': False},
                    'scan_paths': {'type': 'array', 'default': []},
                    'scan_extensions': {'type': 'array', 'default': ['.docx', '.xlsx', '.pdf', '.txt']},
                    'keywords': {'type': 'array', 'default': ['clasificado', 'secreto', 'restringido']},
                },
            },
        },
    })


@api_view(['DELETE'])
def delete_agent(request, agent_id):
    try:
        agent = Agent.objects.get(agent_id=agent_id)
    except Agent.DoesNotExist:
        return Response({'error': 'Agent not found'}, status=status.HTTP_404_NOT_FOUND)

    hostname = agent.hostname
    agent.delete()
    return Response({'status': 'ok', 'message': f'Agent "{hostname}" deleted'})


@api_view(['POST'])
def send_command(request, agent_id):
    try:
        agent = Agent.objects.get(agent_id=agent_id)
    except Agent.DoesNotExist:
        return Response({'error': 'Agent not found'}, status=status.HTTP_404_NOT_FOUND)

    command_type = request.data.get('command_type', '')
    payload = request.data.get('payload', {})

    if command_type not in [c[0] for c in COMMAND_TYPE_CHOICES]:
        return Response({'error': 'Invalid command type'}, status=status.HTTP_400_BAD_REQUEST)

    cmd = AgentCommand.objects.create(
        agent=agent,
        command_type=command_type,
        payload=payload,
    )

    return Response({
        'status': 'ok',
        'command_id': str(cmd.command_id),
        'message': f'Command "{command_type}" queued for agent',
    })
