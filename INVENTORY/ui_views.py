from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.db.models import Count, Q
from django.db.models.functions import TruncDate
from django.utils import timezone
from django.http import JsonResponse
from datetime import timedelta

from .models import Agent, HardwareInventory, SoftwareInventory, AgentCommand


@login_required
def inventory_dashboard(request):
    now = timezone.now()
    agents = Agent.objects
    total = agents.count()
    online = agents.filter(status='online').count()
    offline = agents.filter(status='offline').count()
    pending = agents.filter(status='pending').count()

    recent_agents = agents.order_by('-last_heartbeat')[:10]
    os_dist = dict(
        agents.values('os_type').annotate(c=Count('agent_id')).order_by('-c').values_list('os_type', 'c')
    )
    agents_by_day = list(
        agents.filter(registered_at__gte=now - timedelta(days=30))
        .annotate(day=TruncDate('registered_at'))
        .values('day')
        .annotate(count=Count('agent_id'))
        .order_by('day')
    )

    offline_agents = agents.filter(status='offline').order_by('-last_heartbeat')[:5]
    agents_no_inventory = agents.filter(last_inventory_at__isnull=True)[:5]

    context = {
        'total': total,
        'online': online,
        'offline': offline,
        'pending': pending,
        'recent_agents': recent_agents,
        'os_dist': os_dist,
        'agents_by_day': agents_by_day,
        'offline_agents': offline_agents,
        'agents_no_inventory': agents_no_inventory,
    }
    return render(request, 'inventory/dashboard.html', context)


@login_required
def agents_list(request):
    qs = Agent.objects.all()
    status_filter = request.GET.get('status', '')
    os_filter = request.GET.get('os_type', '')
    search = request.GET.get('search', '')

    if status_filter:
        qs = qs.filter(status=status_filter)
    if os_filter:
        qs = qs.filter(os_type=os_filter)
    if search:
        qs = qs.filter(Q(hostname__icontains=search) | Q(ip_address__icontains=search) | Q(machine_name__icontains=search))

    qs = qs.order_by('-last_heartbeat')
    page = request.GET.get('page', 1)
    per_page = 25
    start = (int(page) - 1) * per_page
    end = start + per_page
    agents_page = qs[start:end]
    total_pages = (qs.count() + per_page - 1) // per_page

    context = {
        'agents': agents_page,
        'total': qs.count(),
        'page': int(page),
        'total_pages': total_pages,
        'status_filter': status_filter,
        'os_filter': os_filter,
        'search': search,
        'status_choices': [('online', 'Online'), ('offline', 'Offline'), ('pending', 'Pending'), ('error', 'Error'), ('disabled', 'Disabled')],
        'os_choices': Agent._meta.get_field('os_type').choices,
    }
    return render(request, 'inventory/agents_list.html', context)


@login_required
def agent_detail(request, agent_id):
    agent = get_object_or_404(Agent, agent_id=agent_id)
    hardware = getattr(agent, 'hardware', None)
    software = agent.software.all().order_by('name')[:100]
    commands = agent.commands.all()[:20]

    context = {
        'agent': agent,
        'hardware': hardware,
        'software': software,
        'software_total': agent.software.count(),
        'commands': commands,
    }
    return render(request, 'inventory/agent_detail.html', context)


@login_required
def software_list(request):
    qs = SoftwareInventory.objects.select_related('agent').all()
    search = request.GET.get('search', '')
    agent_id = request.GET.get('agent_id', '')
    type_filter = request.GET.get('software_type', '')

    if search:
        qs = qs.filter(Q(name__icontains=search) | Q(publisher__icontains=search))
    if agent_id:
        qs = qs.filter(agent_id=agent_id)
    if type_filter:
        qs = qs.filter(software_type=type_filter)

    qs = qs.order_by('name')
    page = request.GET.get('page', 1)
    per_page = 50
    start = (int(page) - 1) * per_page
    end = start + per_page
    software_page = qs[start:end]
    total_pages = (qs.count() + per_page - 1) // per_page

    context = {
        'software': software_page,
        'total': qs.count(),
        'page': int(page),
        'total_pages': total_pages,
        'search': search,
        'type_filter': type_filter,
    }
    return render(request, 'inventory/software_list.html', context)
