from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
from django.core.paginator import Paginator
from django.http import JsonResponse

from .models import DlpPolicy, DlpRule, DlpIncident, DlpScanSummary
from django import forms


class DlpPolicyForm(forms.ModelForm):
    class Meta:
        model = DlpPolicy
        fields = ['code', 'name', 'description', 'enabled', 'severity',
                  'scan_paths', 'monitored_extensions', 'max_file_size_mb']
        widgets = {
            'scan_paths': forms.Textarea(attrs={'rows': 3, 'placeholder': 'One path per line: C:\\Users\\n, /home/n'}),
            'monitored_extensions': forms.Textarea(attrs={'rows': 2, 'placeholder': 'One extension per line: .docx, .pdf'}),
        }


class DlpRuleForm(forms.ModelForm):
    class Meta:
        model = DlpRule
        fields = ['policy', 'name', 'pattern', 'match_type', 'classification', 'severity', 'tags', 'enabled']


@login_required
def dlp_dashboard(request):
    now = timezone.now().replace(tzinfo=None)
    hours_24 = now - timedelta(hours=24)
    hours_7 = now - timedelta(hours=168)
    hours_30 = now - timedelta(hours=720)

    total_incidents = DlpIncident.objects.count()
    open_incidents = DlpIncident.objects.filter(status='open').count()
    incidents_24h = DlpIncident.objects.filter(detected_at__gte=hours_24).count()
    incidents_7d = DlpIncident.objects.filter(detected_at__gte=hours_7).count()
    incidents_30d = DlpIncident.objects.filter(detected_at__gte=hours_30).count()

    critical_open = DlpIncident.objects.filter(severity='critical', status='open').count()
    high_open = DlpIncident.objects.filter(severity='high', status='open').count()

    severity_dist = list(
        DlpIncident.objects.filter(detected_at__gte=hours_24)
        .values('severity').annotate(count=Count('id')).order_by('-count')
    )

    classification_dist = list(
        DlpIncident.objects.filter(detected_at__gte=hours_24)
        .values('classification').annotate(count=Count('id')).order_by('-count')
    )

    channel_dist = list(
        DlpIncident.objects.filter(detected_at__gte=hours_24)
        .values('channel').annotate(count=Count('id')).order_by('-count')
    )

    top_agents = list(
        DlpIncident.objects.filter(detected_at__gte=hours_24, remote_agent_id__isnull=False)
        .values('remote_agent_id', 'host_name').annotate(count=Count('id')).order_by('-count')[:8]
    )

    recent_incidents = DlpIncident.objects.select_related().order_by('-detected_at')[:15]

    total_policies = DlpPolicy.objects.count()
    active_policies = DlpPolicy.objects.filter(enabled=True).count()
    total_rules = DlpRule.objects.count()

    context = {
        'total_incidents': total_incidents,
        'open_incidents': open_incidents,
        'incidents_24h': incidents_24h,
        'incidents_7d': incidents_7d,
        'incidents_30d': incidents_30d,
        'critical_open': critical_open,
        'high_open': high_open,
        'severity_dist': severity_dist,
        'classification_dist': classification_dist,
        'channel_dist': channel_dist,
        'top_agents': top_agents,
        'recent_incidents': recent_incidents,
        'total_policies': total_policies,
        'active_policies': active_policies,
        'total_rules': total_rules,
    }
    return render(request, 'dlp/dashboard.html', context)


@login_required
def incidents_list(request):
    qs = DlpIncident.objects.all()

    severity = request.GET.get('severity')
    status_filter = request.GET.get('status')
    classification = request.GET.get('classification')
    channel = request.GET.get('channel')
    search = request.GET.get('q')

    if severity:
        qs = qs.filter(severity=severity)
    if status_filter:
        qs = qs.filter(status=status_filter)
    if classification:
        qs = qs.filter(classification=classification)
    if channel:
        qs = qs.filter(channel=channel)
    if search:
        qs = qs.filter(Q(file_name__icontains=search) | Q(file_path__icontains=search) | Q(actor__icontains=search))

    qs = qs.order_by('-detected_at')
    paginator = Paginator(qs, 50)
    page_num = request.GET.get('page', 1)
    page = paginator.get_page(page_num)

    context = {
        'incidents': page,
        'severity': severity,
        'status_filter': status_filter,
        'classification': classification,
        'channel': channel,
        'search': search,
    }
    return render(request, 'dlp/incidents_list.html', context)


@login_required
def incident_detail(request, pk):
    incident = get_object_or_404(DlpIncident, pk=pk)
    return render(request, 'dlp/incident_detail.html', {'incident': incident})


@login_required
def incident_acknowledge(request, pk):
    incident = get_object_or_404(DlpIncident, pk=pk)
    incident.status = 'acknowledged'
    incident.acknowledged_at = timezone.now()
    incident.acknowledged_by = request.user.username
    incident.save(update_fields=['status', 'acknowledged_at', 'acknowledged_by'])
    messages.success(request, f'Incident {incident.file_name} acknowledged')
    return redirect('dlp-incident-detail', pk=incident.pk)


@login_required
def incident_resolve(request, pk):
    incident = get_object_or_404(DlpIncident, pk=pk)
    status_val = request.POST.get('status', 'resolved')
    notes = request.POST.get('notes', '')
    incident.status = status_val
    incident.resolved_at = timezone.now()
    incident.resolved_by = request.user.username
    incident.resolution_notes = notes
    incident.save(update_fields=['status', 'resolved_at', 'resolved_by', 'resolution_notes'])
    messages.success(request, f'Incident {incident.file_name} resolved')
    return redirect('dlp-incident-detail', pk=incident.pk)


@login_required
def policies_list(request):
    policies = DlpPolicy.objects.prefetch_related('rules').order_by('-created_at')
    context = {'policies': policies}
    return render(request, 'dlp/policies_list.html', context)


@login_required
def policy_create(request):
    if request.method == 'POST':
        form = DlpPolicyForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Policy created successfully')
            return redirect('dlp-policies')
    else:
        form = DlpPolicyForm()
    return render(request, 'dlp/policy_form.html', {'form': form, 'title': 'Create Policy'})


@login_required
def policy_edit(request, code):
    policy = get_object_or_404(DlpPolicy, code=code)
    if request.method == 'POST':
        form = DlpPolicyForm(request.POST, instance=policy)
        if form.is_valid():
            form.save()
            messages.success(request, 'Policy updated successfully')
            return redirect('dlp-policies')
    else:
        form = DlpPolicyForm(instance=policy)
    return render(request, 'dlp/policy_form.html', {'form': form, 'title': f'Edit: {policy.name}'})


@login_required
def policy_delete(request, code):
    policy = get_object_or_404(DlpPolicy, code=code)
    if request.method == 'POST':
        policy.delete()
        messages.success(request, f'Policy {code} deleted')
        return redirect('dlp-policies')
    return render(request, 'dlp/policy_confirm_delete.html', {'policy': policy})


@login_required
def policy_rules(request, code):
    policy = get_object_or_404(DlpPolicy, code=code)
    if request.method == 'POST':
        form = DlpRuleForm(request.POST)
        if form.is_valid():
            rule = form.save(commit=False)
            rule.policy = policy
            rule.save()
            messages.success(request, 'Rule added successfully')
            return redirect('dlp-policy-rules', code=code)
    else:
        form = DlpRuleForm(initial={'policy': policy})
    rules = policy.rules.all().order_by('-created_at')
    return render(request, 'dlp/policy_rules.html', {'policy': policy, 'rules': rules, 'form': form})


@login_required
def rule_delete(request, rule_id):
    rule = get_object_or_404(DlpRule, pk=rule_id)
    policy_code = rule.policy.code
    if request.method == 'POST':
        rule.delete()
        messages.success(request, 'Rule deleted')
    return redirect('dlp-policy-rules', code=policy_code)


@login_required
def scan_summaries(request):
    summaries = DlpScanSummary.objects.order_by('-started_at')[:100]
    context = {'summaries': summaries}
    return render(request, 'dlp/scan_summaries.html', context)
