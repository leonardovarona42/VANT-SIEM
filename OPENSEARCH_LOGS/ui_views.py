from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta, datetime
from django.core.paginator import Paginator
from django.http import JsonResponse

from .models import LogEvent, LogSource, LogRetentionPolicy
from .forms import LogSourceForm, LogRetentionPolicyForm


@login_required
def logs_discovery(request):
    source_types = list(LogSource.objects.values_list('source_type', flat=True).distinct())
    all_source_types = [st[0] for st in LogEvent._meta.get_field('source_type').choices]
    for st in all_source_types:
        if st not in source_types:
            source_types.append(st)

    severities = [s[0] for s in LogEvent._meta.get_field('severity').choices]
    categories = LogEvent.objects.values_list('event_category', flat=True).distinct()

    from django.utils import timezone
    total_events = LogEvent.objects.count()
    total_sources = LogSource.objects.count()

    context = {
        'total_events': total_events,
        'total_sources': total_sources,
        'source_types': list(source_types),
        'severities': severities,
        'categories': list(categories),
    }
    return render(request, 'opensearch_logs/dashboard.html', context)


@login_required
def logs_list(request):
    qs = LogEvent.objects.select_related('source').all()

    source_type = request.GET.get('source_type', '')
    severity = request.GET.get('severity', '')
    host_ip = request.GET.get('host_ip', '')
    category = request.GET.get('category', '')
    search = request.GET.get('q', '')
    hours = request.GET.get('hours', '24')
    ordering = request.GET.get('ordering', '-event_time')

    if source_type:
        qs = qs.filter(source_type=source_type)
    if severity:
        qs = qs.filter(severity=severity)
    if host_ip:
        qs = qs.filter(host_ip=host_ip)
    if category:
        qs = qs.filter(event_category=category)
    if search:
        qs = qs.filter(Q(message__icontains=search) | Q(host_name__icontains=search) | Q(host_ip__icontains=search))
    if hours:
        try:
            cutoff = timezone.now() - timedelta(hours=int(hours))
            qs = qs.filter(event_time__gte=cutoff)
        except ValueError:
            pass

    qs = qs.order_by(ordering)

    page = request.GET.get('page', 1)
    paginator = Paginator(qs, 50)
    page_obj = paginator.get_page(page)

    source_types = list(LogSource.objects.values_list('source_type', flat=True).distinct())
    all_source_types = [st[0] for st in LogEvent._meta.get_field('source_type').choices]
    for st in all_source_types:
        if st not in source_types:
            source_types.append(st)

    severities = list(LogEvent.objects.values_list('severity', flat=True).distinct())
    all_severities = [s[0] for s in LogEvent._meta.get_field('severity').choices]
    for s in all_severities:
        if s not in severities:
            severities.append(s)

    categories = LogEvent.objects.values_list('event_category', flat=True).distinct()

    context = {
        'page_obj': page_obj,
        'source_types': list(source_types),
        'severities': list(severities),
        'categories': list(categories),
        'filters': {
            'source_type': source_type,
            'severity': severity,
            'host_ip': host_ip,
            'category': category,
            'search': search,
            'hours': hours,
            'ordering': ordering,
        },
        'total_filtered': paginator.count,
    }
    return render(request, 'opensearch_logs/list.html', context)


@login_required
def log_detail(request, pk):
    event = get_object_or_404(LogEvent.objects.select_related('source'), pk=pk)

    related = LogEvent.objects.filter(
        host_ip=event.host_ip,
        event_time__gte=event.event_time - timedelta(hours=1),
        event_time__lte=event.event_time + timedelta(hours=1),
    ).exclude(pk=event.pk).order_by('event_time')[:10] if event.host_ip else []

    context = {
        'event': event,
        'related_events': related,
    }
    return render(request, 'opensearch_logs/detail.html', context)


@login_required
def logs_sources(request):
    sources = LogSource.objects.all().order_by('-last_seen_at')
    if request.method == 'POST':
        source_id = request.POST.get('source_id')
        if source_id:
            try:
                source = LogSource.objects.get(source_id=source_id)
                source.enabled = not source.enabled
                source.save(update_fields=['enabled'])
                status_text = 'habilitada' if source.enabled else 'deshabilitada'
                messages.success(request, f'Fuente {source_id} {status_text}')
            except LogSource.DoesNotExist:
                messages.error(request, f'Fuente {source_id} no encontrada')
            return redirect('logs-sources')

    context = {'sources': sources}
    return render(request, 'opensearch_logs/sources.html', context)


@login_required
def log_source_create(request):
    if request.method == 'POST':
        form = LogSourceForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Fuente creada exitosamente')
            return redirect('logs-sources')
    else:
        form = LogSourceForm()
    return render(request, 'opensearch_logs/source_form.html', {'form': form, 'title': 'Nueva Fuente de Logs'})


@login_required
def log_source_edit(request, source_id):
    source = get_object_or_404(LogSource, source_id=source_id)
    if request.method == 'POST':
        form = LogSourceForm(request.POST, instance=source)
        if form.is_valid():
            form.save()
            messages.success(request, 'Fuente actualizada exitosamente')
            return redirect('logs-sources')
    else:
        form = LogSourceForm(instance=source)
    return render(request, 'opensearch_logs/source_form.html', {'form': form, 'title': 'Editar Fuente', 'source': source})


@login_required
def log_source_delete(request, source_id):
    source = get_object_or_404(LogSource, source_id=source_id)
    if request.method == 'POST':
        count = source.events.count()
        source.delete()
        messages.success(request, f'Fuente {source_id} eliminada ({count} eventos asociados)')
        return redirect('logs-sources')
    context = {'source': source}
    return render(request, 'opensearch_logs/source_confirm_delete.html', context)


@login_required
def logs_retention(request):
    policies = LogRetentionPolicy.objects.all().order_by('source_type')
    if request.method == 'POST':
        policy_id = request.POST.get('policy_id')
        if policy_id:
            try:
                policy = LogRetentionPolicy.objects.get(id=policy_id)
                policy.retention_days = int(request.POST.get('retention_days', policy.retention_days))
                policy.auto_delete = request.POST.get('auto_delete') == 'on'
                policy.save()
                messages.success(request, f'Politica para {policy.source_type} actualizada')
            except (LogRetentionPolicy.DoesNotExist, ValueError):
                messages.error(request, 'Error al actualizar politica')
            return redirect('logs-retention')

    context = {'policies': policies}
    return render(request, 'opensearch_logs/retention.html', context)


@login_required
def run_cleanup_now(request):
    from .tasks import cleanup_old_logs
    result = cleanup_old_logs.delay()
    messages.success(request, 'Limpieza de logs iniciada. Se ejecutara en segundo plano.')
    return redirect('logs-retention')


@login_required
def suricata_dashboard(request):
    hours = int(request.GET.get('hours', 24))
    cutoff = timezone.now() - timedelta(hours=hours)
    qs = LogEvent.objects.filter(source_type='suricata', event_time__gte=cutoff)

    total_events = qs.count()

    sig_qs = qs.filter(parsed_fields__has_key='signature')
    total_signatures = sig_qs.values('parsed_fields__signature').distinct().count()

    top_signatures = list(
        sig_qs.values('parsed_fields__signature')
        .annotate(count=Count('id'))
        .order_by('-count')[:15]
    )

    top_src_ips = list(
        qs.filter(parsed_fields__has_key='src_ip')
        .values('parsed_fields__src_ip')
        .annotate(count=Count('id'))
        .order_by('-count')[:10]
    )

    top_dst_ips = list(
        qs.filter(parsed_fields__has_key='dst_ip')
        .values('parsed_fields__dst_ip')
        .annotate(count=Count('id'))
        .order_by('-count')[:10]
    )

    severity_dist = list(
        qs.values('severity').annotate(count=Count('id')).order_by('-count')
    )

    event_type_dist = list(
        qs.filter(parsed_fields__has_key='event_type')
        .values('parsed_fields__event_type')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    proto_dist = list(
        qs.filter(parsed_fields__has_key='protocol')
        .values('parsed_fields__protocol')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    classtype_dist = list(
        qs.filter(parsed_fields__has_key='classtype')
        .values('parsed_fields__classtype')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    action_dist = list(
        qs.filter(parsed_fields__has_key='action')
        .values('parsed_fields__action')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    top_ports = list(
        qs.filter(parsed_fields__has_key='dst_port')
        .values('parsed_fields__dst_port')
        .annotate(count=Count('id'))
        .order_by('-count')[:10]
    )

    context = {
        'hours': hours,
        'total_events': total_events,
        'total_signatures': total_signatures,
        'top_signatures': top_signatures,
        'top_src_ips': top_src_ips,
        'top_dst_ips': top_dst_ips,
        'severity_dist': severity_dist,
        'event_type_dist': event_type_dist,
        'proto_dist': proto_dist,
        'classtype_dist': classtype_dist,
        'action_dist': action_dist,
        'top_ports': top_ports,
    }
    return render(request, 'opensearch_logs/suricata_dashboard.html', context)


@login_required
def delete_logs_by_filter(request):
    if request.method == 'POST':
        source_type = request.POST.get('source_type', '')
        severity = request.POST.get('severity', '')
        days = int(request.POST.get('days', 0))

        if days <= 0:
            messages.error(request, 'Debe especificar un numero de dias valido')
            return redirect('logs-list')

        cutoff = timezone.now() - timedelta(days=days)
        qs = LogEvent.objects.filter(event_time__lt=cutoff)

        if source_type:
            qs = qs.filter(source_type=source_type)
        if severity:
            qs = qs.filter(severity=severity)

        count = qs.count()
        if count > 0:
            qs.delete()
            messages.success(request, f'{count} logs eliminados (mas viejos de {days} dias)')
        else:
            messages.info(request, 'No hay logs que coincidan con los filtros')

    return redirect('logs-list')
