import logging
import os
import uuid
from datetime import timedelta

from django.db import connection
from django.db.models import Count, Q
from django.db.models.functions import TruncDate
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from .models import (
    Agent, HardwareInventory, SoftwareInventory, AgentCommand,
    ScreenCapture, ProcessSnapshot, COMMAND_TYPE_CHOICES, OS_CHOICES,
)
from .serializers import (
    AgentListSerializer, AgentDetailSerializer, AgentRegisterSerializer,
    HardwareInventorySerializer, SoftwareInventorySerializer,
    AgentCommandSerializer, AgentCommandCreateSerializer,
    HeartbeatSerializer, InventorySubmitSerializer, AgentConfigPushSerializer,
)
from vant_common.auth import generate_agent_token, cache_agent_token
from vant_common.http_client import service_request, AUTH_SERVICE_URL
from vant_common.bus import EventBus

logger = logging.getLogger(__name__)

bus = EventBus("inventory")

BUS_API_URL = os.getenv("BUS_API_URL", "http://127.0.0.1:8600/api/events/receive/")
SERVICE_SECRET = os.getenv("SERVICE_SECRET", "")


def _publish_bus_event(event_type, source_service, payload, severity="info"):
    import requests as http_requests
    body = {
        "event_type": event_type,
        "source_service": source_service,
        "entity_type": "",
        "entity_id": "",
        "actor_user_id": "",
        "actor_username": source_service,
        "payload": payload,
        "severity": severity,
    }
    try:
        resp = http_requests.post(
            BUS_API_URL,
            json=body,
            headers={"X-Service-Secret": SERVICE_SECRET},
            timeout=5,
        )
        if resp.ok:
            logger.info("bus.event published type=%s status=%d", event_type, resp.status_code)
        else:
            logger.warning("bus.event rejected type=%s status=%d", event_type, resp.status_code)
    except Exception as e:
        logger.warning("bus.event publish failed type=%s error=%s", event_type, e)


def _resolve_agent(agent_id_str):
    try:
        uid = uuid.UUID(str(agent_id_str))
        return Agent.objects.get(agent_id=uid)
    except (ValueError, AttributeError, Agent.DoesNotExist):
        return Agent.objects.get(meta__original_agent_id=str(agent_id_str))


@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    try:
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
@permission_classes([AllowAny])
def dashboard_stats(request):
    total = Agent.objects.count()
    online = Agent.objects.filter(status='online').count()
    offline = Agent.objects.filter(status='offline').count()
    pending = Agent.objects.filter(status='pending').count()
    health_pct = round((online / total * 100), 1) if total > 0 else 0

    os_dist = (
        Agent.objects.values('os_type')
        .annotate(count=Count('agent_id'))
        .order_by('-count')
    )
    os_labels = dict(OS_CHOICES)
    os_list = []
    for item in os_dist:
        os_list.append({
            'name': os_labels.get(item['os_type'], item['os_type']),
            'count': item['count'],
            'pct': round((item['count'] / total * 100), 1) if total > 0 else 0,
        })

    recent = (
        Agent.objects.order_by('-last_heartbeat')[:10]
        .values('agent_id', 'hostname', 'ip_address', 'os_type', 'status',
                'last_heartbeat', 'agent_version')
    )
    recent_list = []
    for a in recent:
        recent_list.append({
            'agent_id': str(a['agent_id']),
            'hostname': a['hostname'],
            'ip_address': a['ip_address'] or '-',
            'os_type': os_labels.get(a['os_type'], a['os_type']),
            'status': a['status'],
            'last_heartbeat': a['last_heartbeat'].isoformat() if a['last_heartbeat'] else None,
            'agent_version': a['agent_version'],
        })

    return Response({
        'total': total,
        'online': online,
        'offline': offline,
        'pending': pending,
        'health_pct': health_pct,
        'os_distribution': os_list,
        'recent_agents': recent_list,
    })


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
        agent.save(update_fields=[
            'hostname', 'os_type', 'os_version', 'agent_version',
            'ip_address', 'mac_address', 'domain', 'status',
        ])

    auth_token = generate_agent_token()
    cache_agent_token(auth_token, str(agent.agent_id), ttl=86400)

    try:
        resp = service_request(
            'POST',
            f'{AUTH_SERVICE_URL}/auth/api/agent/token/create/',
            json={
                'agent_id': str(agent.agent_id),
                'hostname': agent.hostname,
                'token': auth_token,
            },
        )
        if resp.status_code not in (200, 201):
            logger.warning("AUTH service token create returned %s", resp.status_code)
    except Exception as e:
        logger.error("Failed to register token with AUTH service: %s", e)

    meta = dict(agent.meta or {})
    meta['auth_token_hash'] = auth_token[:16] + '...'
    agent.meta = meta
    agent.save(update_fields=['meta', 'updated_at'])

    bus.publish_event("agents", "agent_registered", {
        'agent_id': str(agent.agent_id),
        'hostname': agent.hostname,
        'os_type': agent.os_type,
        'created': created,
    })

    return Response({
        'agent_id': str(agent.agent_id),
        'hostname': agent.hostname,
        'status': agent.status,
        'created': created,
        'auth_token': auth_token,
    }, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([AllowAny])
def heartbeat(request):
    serializer = HeartbeatSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    agent_id = serializer.validated_data['agent_id']
    try:
        agent = _resolve_agent(agent_id)
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
        'config_update': None,
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
        agent = _resolve_agent(agent_id)
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

    bus.publish_event("events", "inventory_submitted", {
        'agent_id': str(agent.agent_id),
        'hostname': agent.hostname,
        'software_count': len(sw_data),
    })

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

    bus.publish_event("commands", "command_result", {
        'command_id': str(cmd.command_id),
        'agent_id': str(cmd.agent_id),
        'command_type': cmd.command_type,
        'status': cmd.status,
    })

    return Response({'status': 'ok'})


@api_view(['POST'])
@permission_classes([AllowAny])
def screen_upload(request):
    agent_id = request.data.get('agent_id', '')
    image = request.data.get('image', '')
    if not agent_id or not image:
        return Response({'error': 'agent_id and image required'}, status=status.HTTP_400_BAD_REQUEST)
    try:
        agent = _resolve_agent(agent_id)
    except Agent.DoesNotExist:
        return Response({'error': 'Agent not found'}, status=status.HTTP_404_NOT_FOUND)
    new_cap = ScreenCapture.objects.create(agent=agent, image=image)
    ScreenCapture.objects.filter(agent=agent).exclude(pk=new_cap.pk).delete()
    return Response({'status': 'ok'})


@api_view(['GET'])
@permission_classes([AllowAny])
def screen_latest(request, agent_id):
    try:
        agent = _resolve_agent(agent_id)
    except Agent.DoesNotExist:
        return Response({'error': 'Agent not found'}, status=status.HTTP_404_NOT_FOUND)
    cap = ScreenCapture.objects.filter(agent=agent).first()
    if not cap:
        return Response({'status': 'no_data'})
    return Response({
        'status': 'ok',
        'image': cap.image,
        'captured_at': cap.captured_at.isoformat(),
    })


@api_view(['POST'])
@permission_classes([AllowAny])
def processes_upload(request):
    agent_id = request.data.get('agent_id', '')
    processes = request.data.get('processes', [])
    connections = request.data.get('connections', [])
    if not agent_id:
        return Response({'error': 'agent_id required'}, status=status.HTTP_400_BAD_REQUEST)
    try:
        agent = _resolve_agent(agent_id)
    except Agent.DoesNotExist:
        return Response({'error': 'Agent not found'}, status=status.HTTP_404_NOT_FOUND)
    ProcessSnapshot.objects.create(agent=agent, processes=processes, connections=connections)
    ProcessSnapshot.objects.filter(agent=agent).exclude(
        pk=ProcessSnapshot.objects.filter(agent=agent).first().pk
    ).delete()
    return Response({'status': 'ok'})


@api_view(['GET'])
@permission_classes([AllowAny])
def processes_latest(request, agent_id):
    try:
        agent = _resolve_agent(agent_id)
    except Agent.DoesNotExist:
        return Response({'error': 'Agent not found'}, status=status.HTTP_404_NOT_FOUND)
    snap = ProcessSnapshot.objects.filter(agent=agent).first()
    if not snap:
        return Response({'status': 'no_data'})
    return Response({
        'status': 'ok',
        'processes': snap.processes,
        'connections': snap.connections,
        'captured_at': snap.captured_at.isoformat(),
    })


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
            qs = qs.filter(
                Q(hostname__icontains=search) |
                Q(ip_address__icontains=search) |
                Q(machine_name__icontains=search)
            )

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


@api_view(['POST'])
@permission_classes([AllowAny])
def pull_commands(request):
    agent_id = request.data.get('agent_id', '')
    if not agent_id:
        return Response({'error': 'agent_id required'}, status=status.HTTP_400_BAD_REQUEST)
    try:
        agent = _resolve_agent(agent_id)
    except Agent.DoesNotExist:
        return Response({'error': 'Agent not found'}, status=status.HTTP_404_NOT_FOUND)

    pending = AgentCommand.objects.filter(
        agent=agent, status__in=['pending', 'sent']
    ).order_by('created_at')

    if not pending.exists():
        return Response({'status': 'ok', 'commands': []})

    commands = []
    for cmd in pending:
        cmd.status = 'sent'
        cmd.sent_at = timezone.now()
        cmd.save(update_fields=['status', 'sent_at'])
        commands.append({
            'command_id': str(cmd.command_id),
            'command_type': cmd.command_type,
            'payload': cmd.payload or {},
            'created_at': cmd.created_at.isoformat(),
        })

    return Response({'status': 'ok', 'commands': commands})


@api_view(['POST'])
@permission_classes([AllowAny])
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

    bus.publish_event("commands", "command_created", {
        'command_id': str(cmd.command_id),
        'agent_id': str(agent.agent_id),
        'command_type': command_type,
    })

    return Response({
        'status': 'ok',
        'command_id': str(cmd.command_id),
        'message': f'Command "{command_type}" queued for agent',
    })


@api_view(['DELETE'])
@permission_classes([AllowAny])
def delete_agent(request, agent_id):
    try:
        agent = Agent.objects.get(agent_id=agent_id)
    except Agent.DoesNotExist:
        return Response({'error': 'Agent not found'}, status=status.HTTP_404_NOT_FOUND)

    hostname = agent.hostname
    agent_id_str = str(agent.agent_id)

    try:
        service_request(
            'DELETE',
            f'{AUTH_SERVICE_URL}/auth/api/agent/{agent_id_str}/token/',
        )
    except Exception as e:
        logger.warning("Failed to revoke tokens from AUTH service: %s", e)

    agent.delete()

    bus.publish_event("agents", "agent_deleted", {
        'agent_id': agent_id_str,
        'hostname': hostname,
    })

    return Response({'status': 'ok', 'message': f'Agent "{hostname}" deleted'})


@api_view(['POST'])
@permission_classes([AllowAny])
def services_report(request, agent_id):
    try:
        agent = Agent.objects.get(agent_id=agent_id)
    except Agent.DoesNotExist:
        return Response({'error': 'Agent not found'}, status=status.HTTP_404_NOT_FOUND)

    services_data = request.data.get('services', [])
    if not isinstance(services_data, list):
        return Response({'error': 'services must be a list'}, status=status.HTTP_400_BAD_REQUEST)

    from .models import AgentService
    now = timezone.now()
    events = []

    existing = {s.service_name: s for s in AgentService.objects.filter(agent=agent)}

    seen_names = set()
    for svc in services_data:
        name = svc.get('name', '').strip()
        if not name:
            continue
        seen_names.add(name)
        display = svc.get('description', '')
        active = svc.get('active_state', 'unknown')
        sub = svc.get('sub_state', '')

        prev = existing.get(name)
        if prev:
            old_state = prev.active_state
            prev.active_state = active
            prev.sub_state = sub
            prev.display_name = display or prev.display_name
            prev.last_checked = now
            if old_state != active:
                prev.previous_active_state = old_state
                prev.last_state_change = now
                events.append({
                    'service_name': name,
                    'display_name': display or name,
                    'old_state': old_state,
                    'new_state': active,
                    'is_monitored': prev.is_monitored,
                })
            prev.save(update_fields=[
                'active_state', 'sub_state', 'display_name',
                'last_checked', 'previous_active_state', 'last_state_change',
            ])
        else:
            AgentService.objects.create(
                agent=agent,
                service_name=name,
                display_name=display,
                active_state=active,
                sub_state=sub,
                last_checked=now,
            )

    for name, prev in existing.items():
        if name not in seen_names:
            old_state = prev.active_state
            if old_state != 'inactive':
                prev.previous_active_state = old_state
                prev.active_state = 'inactive'
                prev.sub_state = ''
                prev.last_checked = now
                prev.last_state_change = now
                prev.save(update_fields=[
                    'active_state', 'sub_state', 'last_checked',
                    'previous_active_state', 'last_state_change',
                ])
                if prev.is_monitored:
                    events.append({
                        'service_name': name,
                        'display_name': prev.display_name or name,
                        'old_state': old_state,
                        'new_state': 'inactive',
                        'is_monitored': True,
                    })

    for ev in events:
        if not ev['is_monitored']:
            continue
        agent_info = {
            'agent_id': str(agent.agent_id),
            'hostname': agent.hostname,
            'ip_address': agent.ip_address or '',
            'mac_address': agent.mac_address or '',
            'os_type': agent.os_type,
            'os_version': agent.os_version or '',
            'agent_version': agent.agent_version or '',
            'status': agent.status,
        }
        svc_info = {
            'service_name': ev['service_name'],
            'display_name': ev['display_name'],
            'old_state': ev['old_state'],
            'new_state': ev['new_state'],
        }
        payload = {**agent_info, **svc_info}

        if ev['old_state'] == 'active' and ev['new_state'] != 'active':
            _publish_bus_event("servicio_fallo", "inventory", payload, severity='high')
        elif ev['old_state'] != 'active' and ev['new_state'] == 'active':
            _publish_bus_event("servicio_recuperado", "inventory", payload, severity='info')

    return Response({
        'status': 'ok',
        'services_count': len(seen_names),
        'events_generated': len([e for e in events if e['is_monitored']]),
    })


@api_view(['GET'])
@permission_classes([AllowAny])
def services_list(request, agent_id):
    try:
        agent = Agent.objects.get(agent_id=agent_id)
    except Agent.DoesNotExist:
        return Response({'error': 'Agent not found'}, status=status.HTTP_404_NOT_FOUND)

    from .models import AgentService
    services = AgentService.objects.filter(agent=agent).order_by('service_name')
    data = []
    for s in services:
        data.append({
            'id': s.id,
            'service_name': s.service_name,
            'display_name': s.display_name,
            'active_state': s.active_state,
            'sub_state': s.sub_state,
            'is_monitored': s.is_monitored,
            'previous_active_state': s.previous_active_state,
            'last_checked': s.last_checked.isoformat() if s.last_checked else None,
            'last_state_change': s.last_state_change.isoformat() if s.last_state_change else None,
        })
    return Response({'services': data, 'total': len(data)})


@api_view(['POST'])
@permission_classes([AllowAny])
def services_toggle(request, agent_id):
    try:
        agent = Agent.objects.get(agent_id=agent_id)
    except Agent.DoesNotExist:
        return Response({'error': 'Agent not found'}, status=status.HTTP_404_NOT_FOUND)

    from .models import AgentService
    monitored_names = request.data.get('monitored_services', [])
    if not isinstance(monitored_names, list):
        return Response({'error': 'monitored_services must be a list'}, status=status.HTTP_400_BAD_REQUEST)

    AgentService.objects.filter(agent=agent).update(is_monitored=False)
    if monitored_names:
        AgentService.objects.filter(
            agent=agent, service_name__in=monitored_names
        ).update(is_monitored=True)

    count = AgentService.objects.filter(agent=agent, is_monitored=True).count()
    return Response({'status': 'ok', 'monitored_count': count})
