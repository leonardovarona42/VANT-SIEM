import json
import os
import logging
from datetime import datetime, timedelta
from typing import Dict, Any

import pytz
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.utils import timezone
from django.core.paginator import Paginator
from django.db.models import Q, Count, Avg
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages

from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.utils import timezone
from django.core.paginator import Paginator
from django.db.models import Q, Count, Avg
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages
from .models import (
    SnortLog, SuricataLog, IDSIngestConfig, IDSAlert, IDSStatistics,
    SuricataEveAlert, SuricataFlow, SuricataStats, SuricataSystemLog
)
from .parsers import (
    parse_suricata_line, parse_snort_line, get_log_statistics, validate_log_line,
    parse_suricata_eve_json, parse_suricata_fast_log, parse_suricata_stats_log,
    parse_suricata_system_log, get_suricata_log_type, parse_suricata_log_by_type
)
import json
import os
import logging
from datetime import datetime, timedelta
from typing import Dict, Any



def intelligence_dashboard(request):
    # Aqu� se debe implementar la l�gica real de anal�tica, sugerencias y predicci�n
    intelligence = {
        'most_attacked_segment': '192.168.1.0/24',
        'most_suspicious_ip': '10.0.0.5',
        'peak_hour': '14:00-15:00',
        'top_attack_type': 'Port Scan',
        'correlated_alerts': 15,
        'anomalous_events': 8,
        'recommendation': 'Reforzar reglas de firewall para el segmento m�s atacado.',
        'prediction_labels': ['Lun','Mar','Mi�','Jue','Vie','S�b','Dom'],
        'prediction_values': [12, 15, 9, 18, 22, 17, 14],
        'analytics_labels': ['Snort','Suricata','An�malos','Correlacionados'],
        'analytics_values': [120, 95, 8, 15],
    }
    return render(request, 'intelligence_dashboard.html', {'intelligence': intelligence})



def get_suricata_chart_data(logs, start_time):
    """Generar datos para gráficos de Suricata (Alertas EVE)"""
    now = timezone.now()
    # Timeline (últimas 24 horas por hora)
    timeline_data = []
    for i in range(24):
        hour_start = now - timedelta(hours=i+1)
        hour_end = now - timedelta(hours=i)
        count = logs.filter(timestamp__gte=hour_start, timestamp__lt=hour_end).count()
        timeline_data.append({
            'hour': hour_start.strftime('%H:00'),
            'count': count
        })
    timeline_data.reverse()

    # Distribución de protocolos
    proto_dist = list(logs.values('proto').annotate(count=Count('id')).order_by('-count')[:10])

    # Top puertos origen (solo los que tienen puerto)
    top_src_ports = list(logs.exclude(src_port__isnull=True).values('src_port').annotate(count=Count('id')).order_by('-count')[:10])

    # Top puertos destino (solo los que tienen puerto)
    top_dest_ports = list(logs.exclude(dest_port__isnull=True).values('dest_port').annotate(count=Count('id')).order_by('-count')[:10])

    # Top IPs origen
    top_src_ips = list(logs.values('src_ip').annotate(count=Count('id')).order_by('-count')[:10])

    # Top IPs destino
    top_dest_ips = list(logs.values('dest_ip').annotate(count=Count('id')).order_by('-count')[:10])

    return {
        'timeline': timeline_data,
        'proto_dist': proto_dist,
        'top_src_ports': top_src_ports,
        'top_dest_ports': top_dest_ports,
        'top_src_ips': top_src_ips,
        'top_dest_ips': top_dest_ips,
    }

def intelligence_dashboard(request):
    """Dashboard de Inteligencia y Analítica con estadísticas reales del sistema de gestión de eventos"""
    from EVENT_M.models import Reporte, Incidente, Involucrado, Medida, Area, Servicio, Subcategoria
    from django.db.models import Count, Q, Avg, Max, Min
    import ipaddress

    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)
    last_30d = now - timedelta(days=30)

    intelligence = {}

    # ===== ESTADÍSTICAS GENERALES DEL SISTEMA =====
    intelligence['system_stats'] = {
        'total_reportes': Reporte.objects.count(),
        'total_incidentes': Incidente.objects.count(),
        'total_involucrados': Involucrado.objects.count(),
        'total_areas': Area.objects.count(),
        'total_servicios': Servicio.objects.count(),
        'total_medidas': Medida.objects.count(),
        'reportes_ultimas_24h': Reporte.objects.filter(fecha_hora__gte=last_24h).count(),
        'incidentes_ultimas_24h': Incidente.objects.filter(fecha_hora__gte=last_24h).count(),
        'incidentes_activos': Incidente.objects.filter(estado_solucion__in=['abierto', 'investigacion', 'mitigacion']).count(),
    }

    # ===== ANÁLISIS DE REPORTES =====
    reportes_por_estado_raw = list(Reporte.objects.values('estado_solucion').annotate(
        total=Count('id')
    ).order_by('-total'))

    # Calcular porcentajes después de la consulta
    total_reportes = intelligence['system_stats']['total_reportes']
    reportes_por_estado = []
    for item in reportes_por_estado_raw:
        porcentaje = round((item['total'] / total_reportes) * 100, 1) if total_reportes > 0 else 0
        reportes_por_estado.append({
            'estado_solucion': item['estado_solucion'],
            'total': item['total'],
            'porcentaje': porcentaje
        })

    reportes_por_area = list(Reporte.objects.values('area__nombre').annotate(
        total=Count('id')
    ).filter(total__gt=0).order_by('-total')[:10])

    intelligence['reportes_analysis'] = {
        'por_estado': reportes_por_estado,
        'por_area': reportes_por_area,
        'promedio_por_dia': round(total_reportes / 30, 1) if total_reportes > 0 else 0,
        'tasa_resolucion': round((reportes_por_estado[0]['total'] / total_reportes) * 100, 1) if reportes_por_estado and total_reportes > 0 else 0,
    }

    # ===== ANÁLISIS DE INCIDENTES =====
    incidentes_por_estado_raw = list(Incidente.objects.values('estado_solucion').annotate(
        total=Count('id')
    ).order_by('-total'))

    # Calcular porcentajes después de la consulta
    total_incidentes = intelligence['system_stats']['total_incidentes']
    incidentes_por_estado = []
    for item in incidentes_por_estado_raw:
        porcentaje = round((item['total'] / total_incidentes) * 100, 1) if total_incidentes > 0 else 0
        incidentes_por_estado.append({
            'estado_solucion': item['estado_solucion'],
            'total': item['total'],
            'porcentaje': porcentaje
        })

    incidentes_por_area = list(Incidente.objects.values('areas__nombre').annotate(
        total=Count('id')
    ).filter(total__gt=0).order_by('-total')[:10])

    incidentes_por_servicio = list(Incidente.objects.values('servicios__nombre').annotate(
        total=Count('id')
    ).filter(total__gt=0).order_by('-total')[:10])

    intelligence['incidentes_analysis'] = {
        'por_estado': incidentes_por_estado,
        'por_area': incidentes_por_area,
        'por_servicio': incidentes_por_servicio,
        'promedio_por_dia': round(total_incidentes / 30, 1) if total_incidentes > 0 else 0,
        'tasa_resolucion': round((incidentes_por_estado[0]['total'] / total_incidentes) * 100, 1) if incidentes_por_estado and total_incidentes > 0 else 0,
    }

    # ===== RELACIONES ENTRE INVOLUCRADOS E INCIDENTES =====
    # IPs de involucrados encontradas en logs de IDS
    involucrados_con_ip = []
    for involucrado in Involucrado.objects.all():
        # Buscar IP en logs de Snort
        snort_logs = SnortLog.objects.filter(
            Q(src_ip=involucrado.ip) | Q(dst_ip=involucrado.ip)
        ).order_by('-timestamp')[:5]

        # Buscar IP en logs de Suricata
        suricata_logs = SuricataEveAlert.objects.filter(
            Q(src_ip=involucrado.ip) | Q(dest_ip=involucrado.ip)
        ).order_by('-timestamp')[:5]

        if snort_logs.exists() or suricata_logs.exists():
            involucrados_con_ip.append({
                'involucrado': involucrado,
                'snort_alerts': snort_logs.count(),
                'suricata_alerts': suricata_logs.count(),
                'ultima_actividad_snort': snort_logs.first().timestamp if snort_logs.exists() else None,
                'ultima_actividad_suricata': suricata_logs.first().timestamp if suricata_logs.exists() else None,
                'severidad_promedio': round((snort_logs.aggregate(avg=Avg('priority'))['avg'] or 0) + (suricata_logs.aggregate(avg=Avg('severity'))['avg'] or 0), 1),
            })

    intelligence['involucrados_ip_analysis'] = {
        'total_involucrados_con_ip': len(involucrados_con_ip),
        'porcentaje_involucrados_con_logs': round((len(involucrados_con_ip) / intelligence['system_stats']['total_involucrados']) * 100, 1) if intelligence['system_stats']['total_involucrados'] > 0 else 0,
        'involucrados_detallados': involucrados_con_ip[:20],  # Top 20
        'ips_mas_activas': sorted(involucrados_con_ip, key=lambda x: x['snort_alerts'] + x['suricata_alerts'], reverse=True)[:10],
    }

    # ===== ANÁLISIS DE ALERTAS REPETIDAS =====
    # Alertas críticas y de alta prioridad que se repiten
    try:
        alertas_repetidas = []

        # Snort alerts críticas y altas
        snort_critical = SnortLog.objects.filter(severity__in=['Critical', 'High']).values('message', 'src_ip', 'dst_ip').annotate(
            count=Count('id'),
            ultima_ocurrencia=Max('timestamp'),
            primera_ocurrencia=Min('timestamp')
        ).filter(count__gt=1).order_by('-count')[:20]

        for alert in snort_critical:
            ip_involucrada = Involucrado.objects.filter(ip__in=[alert['src_ip'], alert['dst_ip']]).exists()
            alertas_repetidas.append({
                'tipo': 'Snort',
                'mensaje': alert['message'][:100],
                'ip_origen': alert['src_ip'],
                'ip_destino': alert['dst_ip'],
                'repeticiones': alert['count'],
                'ultima_ocurrencia': alert['ultima_ocurrencia'],
                'primera_ocurrencia': alert['primera_ocurrencia'],
                'duracion_dias': (alert['ultima_ocurrencia'] - alert['primera_ocurrencia']).days if alert['ultima_ocurrencia'] and alert['primera_ocurrencia'] else 0,
                'ip_involucrada': ip_involucrada,
                'severidad': 'Crítica/Alta',
                'recomendacion_reporte': alert['count'] >= 5,
            })

        # Suricata alerts críticas y altas
        suricata_critical = SuricataEveAlert.objects.filter(severity__in=[1, 2]).values('message', 'src_ip', 'dest_ip').annotate(
            count=Count('id'),
            ultima_ocurrencia=Max('timestamp'),
            primera_ocurrencia=Min('timestamp')
        ).filter(count__gt=1).order_by('-count')[:20]

        for alert in suricata_critical:
            ip_involucrada = Involucrado.objects.filter(ip__in=[alert['src_ip'], alert['dest_ip']]).exists()
            alertas_repetidas.append({
                'tipo': 'Suricata',
                'mensaje': alert['message'][:100],
                'ip_origen': alert['src_ip'],
                'ip_destino': alert['dest_ip'],
                'repeticiones': alert['count'],
                'ultima_ocurrencia': alert['ultima_ocurrencia'],
                'primera_ocurrencia': alert['primera_ocurrencia'],
                'duracion_dias': (alert['ultima_ocurrencia'] - alert['primera_ocurrencia']).days if alert['ultima_ocurrencia'] and alert['primera_ocurrencia'] else 0,
                'ip_involucrada': ip_involucrada,
                'severidad': 'Crítica/Alta',
                'recomendacion_reporte': alert['count'] >= 5,
            })

        intelligence['alertas_repetidas'] = {
            'total_alertas_repetidas': len(alertas_repetidas),
            'alertas_para_reporte': len([a for a in alertas_repetidas if a['recomendacion_reporte']]),
            'porcentaje_para_reporte': round((len([a for a in alertas_repetidas if a['recomendacion_reporte']]) / len(alertas_repetidas)) * 100, 1) if alertas_repetidas else 0,
            'alertas_detalladas': sorted(alertas_repetidas, key=lambda x: x['repeticiones'], reverse=True)[:15],
            'top_ips_repetidas': {},
        }

        # Top IPs con alertas repetidas
        all_ips = {}
        for alert in alertas_repetidas:
            for ip_field in ['ip_origen', 'ip_destino']:
                ip = alert[ip_field]
                if ip and ip != '0.0.0.0':
                    if ip not in all_ips:
                        all_ips[ip] = {'count': 0, 'alerts': []}
                    all_ips[ip]['count'] += alert['repeticiones']
                    all_ips[ip]['alerts'].append(alert['mensaje'][:50])

        intelligence['alertas_repetidas']['top_ips_repetidas'] = sorted(
            [{'ip': ip, 'total_repeticiones': data['count'], 'alerts_unicas': len(set(data['alerts']))} for ip, data in all_ips.items()],
            key=lambda x: x['total_repeticiones'],
            reverse=True
        )[:10]
    except Exception as e:
        # Fallback si hay error en las consultas de alertas repetidas
        alertas_repetidas = []
        intelligence['alertas_repetidas'] = {
            'total_alertas_repetidas': 0,
            'alertas_para_reporte': 0,
            'porcentaje_para_reporte': 0,
            'alertas_detalladas': [],
            'top_ips_repetidas': []
        }

    # ===== SEGMENTOS MÁS ATACADOS =====
    # Análisis de segmentos de red más afectados
    segmentos_afectados = {}

    # Analizar IPs de Snort
    for log in SnortLog.objects.filter(timestamp__gte=last_7d):
        for ip in [log.src_ip, log.dst_ip]:
            if ip and ip != '0.0.0.0':
                try:
                    # Intentar determinar segmento /24
                    partes = ip.split('.')
                    if len(partes) == 4:
                        segmento = f"{partes[0]}.{partes[1]}.{partes[2]}.0/24"
                        if segmento not in segmentos_afectados:
                            segmentos_afectados[segmento] = {'count': 0, 'ips': set()}
                        segmentos_afectados[segmento]['count'] += 1
                        segmentos_afectados[segmento]['ips'].add(ip)
                except:
                    continue

    # Analizar IPs de Suricata
    for log in SuricataEveAlert.objects.filter(timestamp__gte=last_7d):
        for ip in [log.src_ip, log.dest_ip]:
            if ip and ip != '0.0.0.0':
                try:
                    partes = ip.split('.')
                    if len(partes) == 4:
                        segmento = f"{partes[0]}.{partes[1]}.{partes[2]}.0/24"
                        if segmento not in segmentos_afectados:
                            segmentos_afectados[segmento] = {'count': 0, 'ips': set()}
                        segmentos_afectados[segmento]['count'] += 1
                        segmentos_afectados[segmento]['ips'].add(ip)
                except:
                    continue

    intelligence['segmentos_afectados'] = sorted(
        [{'segmento': seg, 'total_alertas': data['count'], 'ips_unicas': len(data['ips'])} for seg, data in segmentos_afectados.items()],
        key=lambda x: x['total_alertas'],
        reverse=True
    )[:10]

    # ===== MÉTRICAS PARA GRÁFICOS =====
    # Datos para gráficos de tendencias
    dias_7 = []
    for i in range(7):
        fecha = (now - timedelta(days=i)).date()
        reportes_dia = Reporte.objects.filter(fecha_hora__date=fecha).count()
        incidentes_dia = Incidente.objects.filter(fecha_hora__date=fecha).count()
        alertas_dia = SnortLog.objects.filter(timestamp__date=fecha).count() + SuricataEveAlert.objects.filter(timestamp__date=fecha).count()
        dias_7.append({
            'fecha': fecha.strftime('%d/%m'),
            'reportes': reportes_dia,
            'incidentes': incidentes_dia,
            'alertas': alertas_dia
        })
    dias_7.reverse()

    intelligence['chart_data'] = {
        'tendencias_7_dias': dias_7,
        'distribucion_alertas': [
            {'tipo': 'Snort', 'cantidad': SnortLog.objects.filter(timestamp__gte=last_7d).count()},
            {'tipo': 'Suricata', 'cantidad': SuricataEveAlert.objects.filter(timestamp__gte=last_7d).count()},
            {'tipo': 'Críticas', 'cantidad': SnortLog.objects.filter(timestamp__gte=last_7d, severity='Critical').count() + SuricataEveAlert.objects.filter(timestamp__gte=last_7d, severity=1).count()},
        ],
        'correlaciones': [
            {'tipo': 'Reportes con Incidentes', 'cantidad': Incidente.objects.exclude(reporte=None).count()},
            {'tipo': 'Involucrados con Logs', 'cantidad': len(involucrados_con_ip)},
            {'tipo': 'Alertas Repetidas', 'cantidad': len(alertas_repetidas)},
        ]
    }

    # Convertir chart_data a JSON serializable
    import json
    intelligence['chart_data_json'] = json.dumps(intelligence['chart_data'])

    # ===== RECOMENDACIONES INTELIGENTES =====
    recomendaciones = []

    if intelligence['alertas_repetidas']['alertas_para_reporte'] > 0:
        recomendaciones.append(f"🔴 {intelligence['alertas_repetidas']['alertas_para_reporte']} alertas repetidas requieren conversión a reportes")

    if intelligence['involucrados_ip_analysis']['total_involucrados_con_ip'] > 0:
        recomendaciones.append(f"📊 {intelligence['involucrados_ip_analysis']['total_involucrados_con_ip']} involucrados tienen actividad en logs IDS")

    segmento_mas_atacado = intelligence['segmentos_afectados'][0]['segmento'] if intelligence['segmentos_afectados'] else None
    if segmento_mas_atacado:
        recomendaciones.append(f"🛡️ Reforzar seguridad en segmento {segmento_mas_atacado}")

    if intelligence['system_stats']['incidentes_activos'] > 5:
        recomendaciones.append(f"⚠️ {intelligence['system_stats']['incidentes_activos']} incidentes activos requieren atención inmediata")

    intelligence['recomendaciones'] = recomendaciones

    # ===== DATOS PARA TEMPLATE =====
    # Mantener compatibilidad con template existente
    intelligence.update({
        'most_attacked_segment': segmento_mas_atacado or 'No disponible',
        'most_suspicious_ip': intelligence['alertas_repetidas']['top_ips_repetidas'][0]['ip'] if intelligence['alertas_repetidas']['top_ips_repetidas'] else 'No disponible',
        'peak_hour': 'Análisis en desarrollo',
        'top_attack_type': 'Múltiple',
        'correlated_alerts': intelligence['alertas_repetidas']['total_alertas_repetidas'],
        'anomalous_events': intelligence['involucrados_ip_analysis']['total_involucrados_con_ip'],
        'recommendation': recomendaciones[0] if recomendaciones else 'Sistema funcionando correctamente',
        'prediction_labels': [d['fecha'] for d in dias_7],
        'prediction_values': [d['alertas'] for d in dias_7],
        'analytics_labels': ['Reportes', 'Incidentes', 'Involucrados', 'Alertas'],
        'analytics_values': [
            intelligence['system_stats']['total_reportes'],
            intelligence['system_stats']['total_incidentes'],
            intelligence['system_stats']['total_involucrados'],
            intelligence['alertas_repetidas']['total_alertas_repetidas']
        ],
    })

    return render(request, 'intelligence_dashboard.html', {'intelligence': intelligence})


logger = logging.getLogger(__name__)

@login_required
def snort_dashboard(request):
    """Dashboard de Snort con filtros y paginación"""
    # Parámetros de filtro
    log_type = request.GET.get('log_type', 'alerts')
    time_range = request.GET.get('time_range', '1h')
    start_time_str = request.GET.get('start_time', '')
    end_time_str = request.GET.get('end_time', '')
    severity_filter = request.GET.get('severity', '')
    src_ip_filter = request.GET.get('src_ip', '')
    dst_ip_filter = request.GET.get('dst_ip', '')
    protocol_filter = request.GET.get('protocol', '')
    search_query = request.GET.get('search', '')
    
    # Calcular rango de tiempo
    now = timezone.now()
    # Si el usuario seleccionó un rango personalizado, usarlo
    if start_time_str:
        try:
            start_time = timezone.make_aware(datetime.strptime(start_time_str, '%Y-%m-%dT%H:%M'))
        except Exception:
            start_time = now - timedelta(minutes=5)
    else:
        if time_range == '5m':
            start_time = now - timedelta(minutes=5)
        elif time_range == '10m':
            start_time = now - timedelta(minutes=10)
        elif time_range == '15m':
            start_time = now - timedelta(minutes=15)
        elif time_range == '30m':
            start_time = now - timedelta(minutes=30)
        elif time_range == '1h':
            start_time = now - timedelta(hours=1)
        elif time_range == '2h':
            start_time = now - timedelta(hours=2)
        elif time_range == '6h':
            start_time = now - timedelta(hours=6)
        elif time_range == '12h':
            start_time = now - timedelta(hours=12)
        elif time_range == '24h':
            start_time = now - timedelta(hours=24)
        elif time_range == '7d':
            start_time = now - timedelta(days=7)
        elif time_range == '14d':
            start_time = now - timedelta(days=14)
        elif time_range == '1m':
            start_time = now - timedelta(days=30)
        elif time_range == '3m':
            start_time = now - timedelta(days=90)
        elif time_range == '6m':
            start_time = now - timedelta(days=180)
        elif time_range == '1y':
            start_time = now - timedelta(days=365)
        else:
            start_time = now - timedelta(minutes=5)
    if end_time_str:
        try:
            end_time = timezone.make_aware(datetime.strptime(end_time_str, '%Y-%m-%dT%H:%M'))
        except Exception:
            end_time = now
    else:
        end_time = now
    # Construir query base
    logs = SnortLog.objects.filter(timestamp__gte=start_time, timestamp__lte=end_time)
    
    # Aplicar filtros
    if severity_filter:
        logs = logs.filter(severity=severity_filter)
    if src_ip_filter:
        logs = logs.filter(src_ip__icontains=src_ip_filter)
    if dst_ip_filter:
        logs = logs.filter(dst_ip__icontains=dst_ip_filter)
    if protocol_filter:
        logs = logs.filter(protocol=protocol_filter)
    if search_query:
        logs = logs.filter(
            Q(message__icontains=search_query) |
            Q(src_ip__icontains=search_query) |
            Q(dst_ip__icontains=search_query)
        )
    
    # Top source IPs (24h)
    top_src_ips = SnortLog.objects.filter(
        timestamp__gte=now - timedelta(hours=24)
    ).values('src_ip').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    # Datos para gráficos
    chart_data = get_snort_chart_data(logs, start_time)
    
    # Paginación
    logs = logs.order_by('-timestamp')
    paginator = Paginator(logs, 50)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Obtener opciones para filtros
    severities = SnortLog.objects.values_list('severity', flat=True).distinct().order_by('severity')
    protocols = SnortLog.objects.values_list('protocol', flat=True).distinct().order_by('protocol')
    
    # Estadísticas para el dashboard
    stats = {
        'total': logs.count(),
        'critical': logs.filter(severity='Critical').count(),
        'high': logs.filter(severity='High').count(),
        'medium': logs.filter(severity='Medium').count(),
        'low': logs.filter(severity='Low').count(),
        'last_24h': SnortLog.objects.filter(timestamp__gte=now - timedelta(hours=24)).count(),
    }

    # Contexto para el template
    context = {
        'logs': page_obj,
        'stats': stats,
        'top_signatures': top_signatures if 'top_signatures' in locals() else [],
        'top_src_ips': top_src_ips,
        'chart': json.dumps(chart_data),
        'chart_data': chart_data,  # También pasar como objeto Python
        'severities': severities,
        'protocols': protocols,
        'log_type': log_type,
        'time_range': time_range,
        'filters': {
            'severity': severity_filter,
            'src_ip': src_ip_filter,
            'dst_ip': dst_ip_filter,
            'protocol': protocol_filter,
            'search': search_query,
            'start_time': start_time_str,
            'end_time': end_time_str,
        }
    }
    
    return render(request, 'snort_dashboard.html', context)

def get_snort_chart_data(logs, start_time):
    """Generar datos para gráficos de Snort"""
    now = timezone.now()
    
    # Timeline (últimas 24 horas por hora)
    timeline_data = []
    for i in range(24):
        hour_start = now - timedelta(hours=i+1)
        hour_end = now - timedelta(hours=i)
        count = logs.filter(timestamp__gte=hour_start, timestamp__lt=hour_end).count()
        timeline_data.append({
            'hour': hour_start.strftime('%H:00'),
            'count': count
        })
    timeline_data.reverse()
    
    # Distribución de protocolos
    proto_dist = list(logs.values('protocol').annotate(count=Count('id')).order_by('-count')[:10])
    
    # Top puertos origen (solo los que tienen puerto)
    top_src_ports = list(logs.exclude(src_port__isnull=True).values('src_port').annotate(count=Count('id')).order_by('-count')[:10])
    
    # Top puertos destino (solo los que tienen puerto)
    top_dest_ports = list(logs.exclude(dst_port__isnull=True).values('dst_port').annotate(count=Count('id')).order_by('-count')[:10])
    
    # Top IPs origen
    top_src_ips = list(logs.values('src_ip').annotate(count=Count('id')).order_by('-count')[:10])
    
    # Top IPs destino
    top_dest_ips = list(logs.values('dst_ip').annotate(count=Count('id')).order_by('-count')[:10])
    
    return {
        'timeline': timeline_data,
        'proto_dist': proto_dist,
        'top_src_ports': top_src_ports,
        'top_dest_ports': top_dest_ports,
        'top_src_ips': top_src_ips,
        'top_dest_ips': top_dest_ips,
    }

@login_required
def snort_dashboard_api(request):
    """API para actualización dinámica del dashboard de Snort"""
    # Parámetros de filtro
    log_type = request.GET.get('log_type', 'alerts')
    time_range = request.GET.get('time_range', '5m')
    severity_filter = request.GET.get('severity', '')
    src_ip_filter = request.GET.get('src_ip', '')
    dst_ip_filter = request.GET.get('dst_ip', '')
    protocol_filter = request.GET.get('protocol', '')
    search_query = request.GET.get('search', '')
    
    # Calcular rango de tiempo
    now = timezone.now()
    if time_range == '5m':
        start_time = now - timedelta(minutes=5)
    elif time_range == '10m':
        start_time = now - timedelta(minutes=10)
    elif time_range == '15m':
        start_time = now - timedelta(minutes=15)
    elif time_range == '30m':
        start_time = now - timedelta(minutes=30)
    elif time_range == '1h':
        start_time = now - timedelta(hours=1)
    elif time_range == '2h':
        start_time = now - timedelta(hours=2)
    elif time_range == '6h':
        start_time = now - timedelta(hours=6)
    elif time_range == '12h':
        start_time = now - timedelta(hours=12)
    elif time_range == '24h':
        start_time = now - timedelta(hours=24)
    elif time_range == '7d':
        start_time = now - timedelta(days=7)
    elif time_range == '14d':
        start_time = now - timedelta(days=14)
    elif time_range == '1m':
        start_time = now - timedelta(days=30)
    elif time_range == '3m':
        start_time = now - timedelta(days=90)
    elif time_range == '6m':
        start_time = now - timedelta(days=180)
    elif time_range == '1y':
        start_time = now - timedelta(days=365)
    else:
        start_time = now - timedelta(minutes=5)
    
    # Construir query base
    logs = SnortLog.objects.filter(timestamp__gte=start_time)
    
    # Aplicar filtros
    if severity_filter:
        logs = logs.filter(severity=severity_filter)
    if src_ip_filter:
        logs = logs.filter(src_ip__icontains=src_ip_filter)
    if dst_ip_filter:
        logs = logs.filter(dst_ip__icontains=dst_ip_filter)
    if protocol_filter:
        logs = logs.filter(protocol=protocol_filter)
    if search_query:
        logs = logs.filter(
            Q(message__icontains=search_query) |
            Q(src_ip__icontains=search_query) |
            Q(dst_ip__icontains=search_query)
        )
    
    # Estadísticas
    stats = {
        'total': logs.count(),
        'critical': logs.filter(severity='Critical').count(),
        'high': logs.filter(severity='High').count(),
        'medium': logs.filter(severity='Medium').count(),
        'low': logs.filter(severity='Low').count(),
        'last_24h': SnortLog.objects.filter(timestamp__gte=now - timedelta(hours=24)).count(),
    }
    
    # Datos para gráficos
    chart_data = get_snort_chart_data(logs, start_time)
    
    # Últimos logs (máximo 50)
    recent_logs = list(logs.order_by('-timestamp')[:50].values(
        'id', 'timestamp', 'severity', 'src_ip', 'dst_ip', 'protocol', 
        'sid', 'message', 'classification', 'ttl'
    ))
    
    return JsonResponse({
        'success': True,
        'stats': stats,
        'chart': chart_data,
        'logs': recent_logs,
        'total_count': logs.count()
    })
    
    return render(request, 'snort_dashboard.html', context)

@login_required
def suricata_dashboard(request):
    """Dashboard de Suricata con múltiples tipos de logs y actualización automática"""
    # Filtros
    log_type = request.GET.get('log_type', 'eve_alerts')
    time_range = request.GET.get('time_range', '5m')
    severity_filter = request.GET.get('severity', '')
    src_ip_filter = request.GET.get('src_ip', '')
    dst_ip_filter = request.GET.get('dst_ip', '')
    protocol_filter = request.GET.get('protocol', '')
    search_query = request.GET.get('search', '')
    
    # Rango de tiempo
    now = timezone.now()
    ranges = {
        '5m': now - timedelta(minutes=5),
        '10m': now - timedelta(minutes=10),
        '15m': now - timedelta(minutes=15),
        '30m': now - timedelta(minutes=30),
        '1h': now - timedelta(hours=1),
        '2h': now - timedelta(hours=2),
        '6h': now - timedelta(hours=6),
        '12h': now - timedelta(hours=12),
        '24h': now - timedelta(hours=24),
        '7d': now - timedelta(days=7),
        '14d': now - timedelta(days=14),
        '1m': now - timedelta(days=30),
        '3m': now - timedelta(days=90),
        '6m': now - timedelta(days=180),
        '1y': now - timedelta(days=365),
    }
    since = ranges.get(time_range, now - timedelta(minutes=5))
    
    # Obtener datos según el tipo de log seleccionado

    if log_type == 'eve_alerts':
        logs = SuricataEveAlert.objects.filter(event_type='alert', timestamp__gte=since)
        if severity_filter:
            severity_map = {'Critical': 1, 'High': 2, 'Medium': 3, 'Low': 4}
            logs = logs.filter(severity=severity_map.get(severity_filter, 1))
        if src_ip_filter:
            logs = logs.filter(src_ip__icontains=src_ip_filter)
        if dst_ip_filter:
            logs = logs.filter(dest_ip__icontains=dst_ip_filter)
        if protocol_filter:
            logs = logs.filter(proto=protocol_filter)
        if search_query:
            logs = logs.filter(
                Q(message__icontains=search_query) |
                Q(src_ip__icontains=search_query) |
                Q(dest_ip__icontains=search_query)
            )

        # Estadísticas para EVE alerts
        stats = {
            'total': logs.count(),
            'critical': logs.filter(severity=1).count(),
            'high': logs.filter(severity=2).count(),
            'medium': logs.filter(severity=3).count(),
            'low': logs.filter(severity=4).count(),
            'last_24h': logs.filter(timestamp__gte=timezone.now() - timedelta(hours=24)).count(),
        }

        # Obtener valores únicos para filtros
        severities = ['Critical', 'High', 'Medium', 'Low']
        protocols = logs.values_list('proto', flat=True).distinct()

        # Usar función igual que en Snort
        chart_data = get_suricata_chart_data(logs, since)
        proto_dist = chart_data['proto_dist']
        top_src_ips = chart_data['top_src_ips']
        top_dest_ips = chart_data['top_dest_ips']
        top_src_ports = chart_data['top_src_ports']
        top_dest_ports = chart_data['top_dest_ports']
        timeline = chart_data['timeline']
        
    elif log_type == 'eve_flows':
        logs = SuricataFlow.objects.filter(timestamp__gte=since)
        if src_ip_filter:
            logs = logs.filter(src_ip__icontains=src_ip_filter)
        if dst_ip_filter:
            logs = logs.filter(dest_ip__icontains=dst_ip_filter)
        if protocol_filter:
            logs = logs.filter(proto=protocol_filter)
        if search_query:
            logs = logs.filter(
                Q(src_ip__icontains=search_query) |
                Q(dest_ip__icontains=search_query)
            )
        
        # Estadísticas para flows
        stats = {
            'total': SuricataFlow.objects.count(),
            'last_24h': SuricataFlow.objects.filter(
                timestamp__gte=timezone.now() - timedelta(hours=24)
            ).count(),
            'total_bytes': sum(SuricataFlow.objects.values_list('bytes_toserver', flat=True)) + 
                          sum(SuricataFlow.objects.values_list('bytes_toclient', flat=True)),
            'total_packets': sum(SuricataFlow.objects.values_list('pkts_toserver', flat=True)) + 
                            sum(SuricataFlow.objects.values_list('pkts_toclient', flat=True)),
        }
        
        severities = []
        protocols = SuricataFlow.objects.values_list('proto', flat=True).distinct()
        
        flows_qs = SuricataFlow.objects.filter(timestamp__gte=since)
        flow_proto_dist = list(flows_qs.values('proto').annotate(count=Count('proto')).order_by('-count')[:10])
        flow_top_src_ips = list(flows_qs.values('src_ip').annotate(count=Count('src_ip')).order_by('-count')[:10])
        flow_top_dest_ips = list(flows_qs.values('dest_ip').annotate(count=Count('dest_ip')).order_by('-count')[:10])
        
    elif log_type == 'fast_log':
        logs = SuricataLog.objects.filter(timestamp__gte=since)  # Usar el modelo original para fast.log
        if severity_filter:
            logs = logs.filter(severity=severity_filter)
        if src_ip_filter:
            logs = logs.filter(src_ip__icontains=src_ip_filter)
        if dst_ip_filter:
            logs = logs.filter(dst_ip__icontains=dst_ip_filter)
        if protocol_filter:
            logs = logs.filter(protocol=protocol_filter)
        if search_query:
            logs = logs.filter(
                Q(message__icontains=search_query) |
                Q(src_ip__icontains=search_query) |
                Q(dst_ip__icontains=search_query)
            )
        
        # Estadísticas para fast.log
        stats = {
            'total': SuricataLog.objects.count(),
            'critical': SuricataLog.objects.filter(severity='Critical').count(),
            'high': SuricataLog.objects.filter(severity='High').count(),
            'medium': SuricataLog.objects.filter(severity='Medium').count(),
            'low': SuricataLog.objects.filter(severity='Low').count(),
            'last_24h': SuricataLog.objects.filter(
                timestamp__gte=timezone.now() - timedelta(hours=24)
            ).count(),
        }
        
        severities = SuricataLog.objects.values_list('severity', flat=True).distinct()
        protocols = SuricataLog.objects.values_list('protocol', flat=True).distinct()
        
        fl_qs = SuricataLog.objects.filter(timestamp__gte=since)
        fast_proto_dist = list(fl_qs.values('protocol').annotate(count=Count('protocol')).order_by('-count')[:10])
        fast_top_src_ips = list(fl_qs.values('src_ip').annotate(count=Count('src_ip')).order_by('-count')[:10])
        fast_top_dst_ips = list(fl_qs.values('dst_ip').annotate(count=Count('dst_ip')).order_by('-count')[:10])
        fast_top_src_ports = list(fl_qs.exclude(src_port=None).values('src_port').annotate(count=Count('src_port')).order_by('-count')[:10])
        fast_top_dst_ports = list(fl_qs.exclude(dst_port=None).values('dst_port').annotate(count=Count('dst_port')).order_by('-count')[:10])
        
    elif log_type == 'stats':
        logs = SuricataStats.objects.filter(timestamp__gte=since)
        stats = {
            'total': SuricataStats.objects.count(),
            'last_24h': SuricataStats.objects.filter(
                timestamp__gte=timezone.now() - timedelta(hours=24)
            ).count(),
            'avg_packets_per_sec': SuricataStats.objects.aggregate(
                avg_packets=Avg('packets_per_second')
            )['avg_packets'] or 0,
            'avg_bytes_per_sec': SuricataStats.objects.aggregate(
                avg_bytes=Avg('bytes_per_second')
            )['avg_bytes'] or 0,
        }
        severities = []
        protocols = []
        
    elif log_type == 'system_log':
        logs = SuricataSystemLog.objects.filter(timestamp__gte=since)
        level_filter = request.GET.get('level', '')
        if level_filter:
            logs = logs.filter(level=level_filter)
        if search_query:
            logs = logs.filter(
                Q(message__icontains=search_query) |
                Q(component__icontains=search_query)
            )

        # Estadísticas para system log
        stats = {
            'total': SuricataSystemLog.objects.count(),
            'last_24h': SuricataSystemLog.objects.filter(
                timestamp__gte=timezone.now() - timedelta(hours=24)
            ).count(),
            'errors': SuricataSystemLog.objects.filter(level='ERROR').count(),
            'warnings': SuricataSystemLog.objects.filter(level='WARNING').count(),
        }

        severities = []
        protocols = []
    
    # Paginación
    paginator = Paginator(logs.order_by('-timestamp'), 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    

    # Obtener estadísticas adicionales para el dashboard
    recent_alerts = SuricataEveAlert.objects.filter(
        event_type='alert',
        timestamp__gte=timezone.now() - timedelta(hours=1)
    ).count()


    # Inicializar variables de gráficos y top_signatures para evitar UnboundLocalError
    top_src_ips = []
    top_dest_ips = []
    top_src_ports = []
    top_dest_ports = []
    proto_dist = []
    timeline = []
    top_signatures = []

    # Definir top_signatures y datasets de gráficos usando get_suricata_chart_data si estamos en eve_alerts
    if log_type == 'eve_alerts':
        top_signatures = logs.values('signature_id', 'message').annotate(
            count=Count('signature_id')
        ).order_by('-count')[:10]
        chart_data = get_suricata_chart_data(logs, since)
        proto_dist = chart_data['proto_dist']
        top_src_ips = chart_data['top_src_ips']
        top_dest_ips = chart_data['top_dest_ips']
        top_src_ports = chart_data['top_src_ports']
        top_dest_ports = chart_data['top_dest_ports']
        timeline = chart_data['timeline']
        chart = {
            'proto_dist': proto_dist,
            'top_src_ips': top_src_ips,
            'top_dest_ips': top_dest_ips,
            'top_src_ports': top_src_ports,
            'top_dest_ports': top_dest_ports,
            'timeline': timeline,
        }
    elif log_type == 'eve_flows':
        chart = {
            'proto_dist': flow_proto_dist,
            'top_src_ips': flow_top_src_ips,
            'top_dest_ips': flow_top_dest_ips,
            'top_src_ports': [],
            'top_dest_ports': [],
            'timeline': [],
        }
    elif log_type == 'fast_log':
        chart = {
            'proto_dist': fast_proto_dist,
            'top_src_ips': fast_top_src_ips,
            'top_dest_ips': fast_top_dst_ips,
            'top_src_ports': fast_top_src_ports,
            'top_dest_ports': fast_top_dst_ports,
            'timeline': [],
        }
    else:
        chart = {
            'proto_dist': [],
            'top_src_ips': [],
            'top_dest_ips': [],
            'top_src_ports': [],
            'top_dest_ports': [],
            'timeline': [],
        }

    context = {
        'logs': page_obj,
        'stats': stats,
        'severities': severities,
        'protocols': protocols,
        'log_type': log_type,
        'time_range': time_range,
        'recent_alerts': recent_alerts,
        'top_signatures': top_signatures,
        'top_src_ips': top_src_ips,
        'chart': chart,
        'filters': {
            'severity': severity_filter,
            'src_ip': src_ip_filter,
            'dst_ip': dst_ip_filter,
            'protocol': protocol_filter,
            'search': search_query,
            'level': request.GET.get('level', ''),
        }
    }
    
    return render(request, 'suricata_dashboard.html', context)

@login_required
def ids_config(request):
    """Configuración de IDS/IPS con validaciones mejoradas"""
    configs = IDSIngestConfig.objects.all().order_by('-created_at')
    
    if request.method == 'POST':
        # Agregar configuración
        if 'add_ids_type' in request.POST:
            try:
                config = IDSIngestConfig.objects.create(
                    ids_type=request.POST['add_ids_type'],
                    log_path=request.POST['add_log_path'],
                    active='add_active' in request.POST,
                    retention_days=int(request.POST['add_retention_days'])
                )
                messages.success(request, f'Configuración {config.ids_type.upper()} creada exitosamente')
                return redirect('ids-config')
            except Exception as e:
                messages.error(request, f'Error creando configuración: {e}')
        
        # Editar configuración
        elif 'edit_id' in request.POST:
            try:
                config = get_object_or_404(IDSIngestConfig, id=request.POST['edit_id'])
                config.ids_type = request.POST['edit_ids_type']
                config.log_path = request.POST['edit_log_path']
                config.active = 'edit_active' in request.POST
                config.retention_days = int(request.POST['edit_retention_days'])
                config.save()
                messages.success(request, f'Configuración {config.ids_type.upper()} actualizada exitosamente')
                return redirect('ids-config')
            except Exception as e:
                messages.error(request, f'Error actualizando configuración: {e}')
        
        # Guardar cambios rápidos
        else:
            try:
                for config in configs:
                    config.log_path = request.POST.get(f'log_path_{config.id}', config.log_path)
                    config.active = f'active_{config.id}' in request.POST
                    config.retention_days = int(request.POST.get(f'retention_days_{config.id}', config.retention_days))
                    config.save()
                messages.success(request, 'Configuraciones actualizadas exitosamente')
                return redirect('ids-config')
            except Exception as e:
                messages.error(request, f'Error actualizando configuraciones: {e}')
    
    context = {
        'configs': configs,
        'stats': {
            'total_configs': configs.count(),
            'active_configs': configs.filter(active=True).count(),
            'snort_configs': configs.filter(ids_type='snort').count(),
            'suricata_configs': configs.filter(ids_type='suricata').count(),
        }
    }
    
    return render(request, 'ids_config.html', context)

@login_required
def test_config(request, config_id):
    """Probar configuración con validaciones mejoradas y soporte completo para Snort 3 y Suricata"""
    if request.method == 'POST':
        try:
            config = get_object_or_404(IDSIngestConfig, id=config_id)

            # Aceptar archivo o directorio
            path = config.log_path
            if not os.path.exists(path):
                return JsonResponse({
                    'success': False,
                    'error': 'Ruta no existe',
                    'details': f'Ruta: {path}'
                })

            # Si es archivo específico, procesarlo directamente
            if os.path.isfile(path):
                filename = os.path.basename(path)
                stats = get_log_statistics(path, config.ids_type)

                if stats.get('parsed_lines', 0) == 0:
                    if stats.get('error'):
                        return JsonResponse({'success': False, 'error': stats['error']})
                    else:
                        return JsonResponse({
                            'success': False,
                            'error': 'No se encontraron líneas parseables',
                            'details': f'Archivo: {filename}, Total líneas: {stats.get("total_lines", 0)}, Errores: {stats.get("error_lines", 0)}'
                        })

                # Intentar ejecutar ingesta para archivo específico
                from django.core.management import call_command
                from io import StringIO

                output = StringIO()
                try:
                    if config.ids_type == 'snort':
                        # Para archivos específicos de Snort, usar el servicio optimizado
                        from ids_ingest.services import ingest_service
                        ingest_service._process_snort_config(config)
                        result = "Procesamiento completado usando servicio optimizado"
                    else:  # suricata
                        call_command('ingest_suricata_logs', log_dir=os.path.dirname(path), verbosity=0, stdout=output)
                        result = output.getvalue()

                    stats['ingested_lines'] = len(result.split('\n')) if result else 0

                except Exception as e:
                    stats['ingest_error'] = str(e)

                return JsonResponse({
                    'success': True,
                    'message': f'Archivo {filename} válido - {stats.get("parsed_lines", 0)} líneas parseables',
                    'stats': stats,
                    'file_info': {
                        'name': filename,
                        'size': os.path.getsize(path),
                        'type': config.ids_type
                    }
                })

            # Si es directorio, detectar archivos relevantes según el tipo de IDS
            if os.path.isdir(path):
                if config.ids_type == 'suricata':
                    candidates = ['eve.json', 'fast.log', 'stats.log', 'suricata.log']
                    not_found_msg = 'No se encontraron archivos de Suricata dentro del directorio'
                    success_msg = 'Se detectaron {n} archivos de Suricata en el directorio'
                elif config.ids_type == 'snort':
                    # Incluir todas las variaciones de archivos Snort
                    candidates = [
                        'alert.full', 'alert_full.txt', 'alert.full.txt',  # archivos full
                        'alerts.fast', 'alert.fast', 'alert_fast.txt',     # archivos fast
                        'alerts.csv', 'snort.log'                          # otros
                    ]
                    not_found_msg = 'No se encontraron archivos de Snort dentro del directorio'
                    success_msg = 'Se detectaron {n} archivos de Snort en el directorio'
                else:
                    candidates = []
                    not_found_msg = 'Tipo de IDS/IPS no soportado'
                    success_msg = 'Se detectaron {n} archivos'

                found = []
                for name in candidates:
                    fp = os.path.join(path, name)
                    if os.path.exists(fp):
                        found.append({
                            'file': name,
                            'size_bytes': os.path.getsize(fp),
                            'type': 'full' if 'full' in name else ('fast' if 'fast' in name else 'other')
                        })

                # Escanear archivos adicionales que podrían existir
                if config.ids_type == 'snort':
                    try:
                        for file_name in os.listdir(path):
                            if file_name.startswith('alert') and (file_name.endswith('.fast') or file_name.endswith('.txt') or file_name.endswith('.full')):
                                fp = os.path.join(path, file_name)
                                if os.path.isfile(fp) and file_name not in [f['file'] for f in found]:
                                    found.append({
                                        'file': file_name,
                                        'size_bytes': os.path.getsize(fp),
                                        'type': 'full' if 'full' in file_name else 'fast'
                                    })
                    except Exception as e:
                        # Ignorar errores de escaneo
                        pass

                if not found:
                    return JsonResponse({
                        'success': False,
                        'error': not_found_msg,
                        'details': f'Directorio: {path}'
                    })

                # Probar parsing de los archivos encontrados
                parsing_results = []
                total_parsed = 0
                total_lines = 0

                for file_info in found[:5]:  # Probar máximo 5 archivos
                    file_path = os.path.join(path, file_info['file'])
                    try:
                        stats = get_log_statistics(file_path, config.ids_type)
                        parsing_results.append({
                            'file': file_info['file'],
                            'parsed_lines': stats.get('parsed_lines', 0),
                            'total_lines': stats.get('total_lines', 0),
                            'error': stats.get('error')
                        })
                        total_parsed += stats.get('parsed_lines', 0)
                        total_lines += stats.get('total_lines', 0)
                    except Exception as e:
                        parsing_results.append({
                            'file': file_info['file'],
                            'parsed_lines': 0,
                            'total_lines': 0,
                            'error': str(e)
                        })

                # Intentar ejecutar ingesta usando el servicio optimizado
                try:
                    from ids_ingest.services import ingest_service
                    ingest_service._process_config(config)
                    ingest_message = "Ingesta ejecutada usando servicio optimizado con threading"
                except Exception as e:
                    ingest_message = f"Error en ingesta: {str(e)}"

                return JsonResponse({
                    'success': True,
                    'message': success_msg.format(n=len(found)),
                    'files': found,
                    'parsing_summary': {
                        'total_files': len(found),
                        'total_parsed_lines': total_parsed,
                        'total_lines': total_lines,
                        'parsing_results': parsing_results
                    },
                    'ingest_result': ingest_message
                })

        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': f'Error probando configuración: {str(e)}'
            })

    return JsonResponse({'success': False, 'error': 'Método no permitido'}, status=405)

@csrf_exempt
@login_required
def toggle_ingest(request, config_id):
    """Activar/desactivar ingesta y gestionar servicio automático usando el servicio optimizado"""
    if request.method == 'POST':
        if not request.user.is_superuser:
            return JsonResponse({'success': False, 'error': 'Solo un superusuario puede cambiar el estado de la ingesta.'}, status=403)
        try:
            from ids_ingest.services import ingest_service
            
            config = get_object_or_404(IDSIngestConfig, id=config_id)
            data = json.loads(request.body)
            new_status = data.get('active', False)
            
            # Cambiar estado
            config.active = new_status
            config.save()
            
            # Si se activa, ejecutar una ingesta inmediata usando el servicio optimizado
            if new_status:
                try:
                    # Usar el servicio optimizado para procesamiento inmediato
                    ingest_service._process_config(config)
                    
                    status = 'activada y ejecutada'
                    message = f'Servicio de ingesta {status} exitosamente. Configuración {config.ids_type.upper()} procesada con threading optimizado.'
                except Exception as e:
                    status = 'activada'
                    message = f'Servicio de ingesta {status} exitosamente, pero hubo un error en la ejecución inicial: {str(e)}'
            else:
                status = 'desactivada'
                message = f'Servicio de ingesta {status} exitosamente'
            
            return JsonResponse({
                'success': True,
                'message': message,
                'status': status
            })
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': f'Error cambiando estado: {str(e)}'
            })
    
    return JsonResponse({'success': False, 'error': 'Método no permitido'}, status=405)

@login_required
def alerts_dashboard(request):
    """Dashboard de alertas críticas"""
    alerts = IDSAlert.objects.all().order_by('-timestamp')
    
    # Filtros
    severity_filter = request.GET.get('severity', '')
    acknowledged_filter = request.GET.get('acknowledged', '')
    
    if severity_filter:
        alerts = alerts.filter(severity=severity_filter)
    if acknowledged_filter == 'true':
        alerts = alerts.filter(acknowledged=True)
    elif acknowledged_filter == 'false':
        alerts = alerts.filter(acknowledged=False)
    
    # Paginación
    paginator = Paginator(alerts, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Estadísticas
    stats = {
        'total': IDSAlert.objects.count(),
        'unacknowledged': IDSAlert.objects.filter(acknowledged=False).count(),
        'critical': IDSAlert.objects.filter(severity='Critical').count(),
        'high': IDSAlert.objects.filter(severity='High').count(),
        'last_24h': IDSAlert.objects.filter(
            timestamp__gte=timezone.now() - timedelta(hours=24)
        ).count(),
    }
    
    context = {
        'alerts': page_obj,
        'stats': stats,
        'filters': {
            'severity': severity_filter,
            'acknowledged': acknowledged_filter,
        }
    }
    
    return render(request, 'alerts_dashboard.html', context)

@csrf_exempt
@login_required
def acknowledge_alert(request, alert_id):
    """Reconocer alerta"""
    if request.method == 'POST':
        try:
            alert = get_object_or_404(IDSAlert, id=alert_id)
            alert.acknowledged = True
            alert.acknowledged_by = request.user
            alert.acknowledged_at = timezone.now()
            alert.save()
            
            return JsonResponse({
                'success': True,
                'message': 'Alerta reconocida exitosamente'
            })
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': f'Error reconociendo alerta: {str(e)}'
            })
    
    return JsonResponse({'success': False, 'error': 'Método no permitido'}, status=405)

@login_required
def statistics_dashboard(request):
    """Dashboard de estadísticas"""
    # Estadísticas por tipo
    snort_stats = IDSStatistics.objects.filter(ids_type='snort').order_by('-date')[:30]
    suricata_stats = IDSStatistics.objects.filter(ids_type='suricata').order_by('-date')[:30]
    
    # Estadísticas generales
    general_stats = {
        'total_snort_logs': SnortLog.objects.count(),
        'total_suricata_logs': SuricataLog.objects.count(),
        'total_alerts': IDSAlert.objects.count(),
        'unacknowledged_alerts': IDSAlert.objects.filter(acknowledged=False).count(),
        'active_configs': IDSIngestConfig.objects.filter(active=True).count(),
    }
    
    context = {
        'snort_stats': snort_stats,
        'suricata_stats': suricata_stats,
        'general_stats': general_stats,
    }
    
    return render(request, 'statistics_dashboard.html', context)

@login_required
def service_management(request):
    """Gestión del servicio de ingesta automática"""
    if not request.user.is_superuser:
        messages.error(request, 'Solo los superusuarios pueden gestionar servicios')
        return redirect('ids-config')
    
    # Obtener configuraciones
    configs = IDSIngestConfig.objects.all().order_by('-created_at')
    
    # Estadísticas del servicio
    active_configs = configs.filter(active=True).count()
    total_configs = configs.count()
    
    # Estadísticas de rotación
    rotation_stats = {
        'total_configs': total_configs,
        'active_configs': active_configs,
        'suricata_configs': configs.filter(ids_type='suricata', active=True).count(),
        'snort_configs': configs.filter(ids_type='snort', active=True).count(),
    }
    
    # Logs recientes
    recent_snort = SnortLog.objects.filter(
        timestamp__gte=timezone.now() - timedelta(hours=24)
    ).count()
    
    recent_suricata = SuricataEveAlert.objects.filter(
        timestamp__gte=timezone.now() - timedelta(hours=24)
    ).count()
    
    # Configuraciones que no se han ejecutado recientemente
    stale_configs = configs.filter(
        active=True,
        last_run__lt=timezone.now() - timedelta(hours=1)
    )
    
    context = {
        'configs': configs,
        'active_configs': active_configs,
        'total_configs': total_configs,
        'rotation_stats': rotation_stats,
        'recent_snort': recent_snort,
        'recent_suricata': recent_suricata,
        'stale_configs': stale_configs,
        'stats': {
            'total_configs': total_configs,
            'active_configs': active_configs,
            'inactive_configs': total_configs - active_configs,
            'recent_logs': recent_snort + recent_suricata,
        }
    }
    
    return render(request, 'service_management.html', context)

@csrf_exempt
@login_required
def start_service(request):
    """Iniciar servicio de ingesta automática usando el servicio optimizado"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'Solo los superusuarios pueden gestionar servicios'}, status=403)

    if request.method == 'POST':
        try:
            from ids_ingest.services import ingest_service

            # Verificar si el servicio ya está ejecutándose
            if ingest_service.running:
                return JsonResponse({
                    'success': False,
                    'error': 'El servicio de ingesta ya está ejecutándose'
                })

            # Ejecutar ingesta para todas las configuraciones activas usando el servicio optimizado
            configs = IDSIngestConfig.objects.filter(active=True)
            processed_count = 0
            errors = []

            for config in configs:
                try:
                    logger.info(f"🔄 Procesando configuración {config.id} desde vista web")
                    ingest_service._process_config(config)

                    # Actualizar last_run después del procesamiento exitoso
                    config.last_run = timezone.now()
                    config.save(update_fields=['last_run'])
                    logger.info(f"✅ Configuración {config.id} procesada y last_run actualizado")

                    processed_count += 1
                except Exception as e:
                    error_msg = f'Error procesando configuración {config.id}: {str(e)}'
                    logger.error(error_msg)
                    errors.append(error_msg)
                    continue

            # Preparar mensaje de respuesta
            message = f'Servicio de ingesta ejecutado exitosamente. {processed_count} configuraciones procesadas con threading optimizado.'
            if errors:
                message += f' Errores encontrados: {len(errors)}'

            response_data = {
                'success': True,
                'message': message,
                'processed_count': processed_count,
                'errors': errors,
                'timestamp': timezone.now().isoformat()
            }

            logger.info(f"✅ Servicio ejecutado desde vista web: {processed_count} configuraciones procesadas")
            return JsonResponse(response_data)

        except Exception as e:
            logger.error(f"❌ Error general ejecutando servicio desde vista web: {e}", exc_info=True)
            return JsonResponse({
                'success': False,
                'error': f'Error ejecutando servicio: {str(e)}',
                'debug_info': {
                    'exception_type': type(e).__name__,
                    'line_number': getattr(e, '__traceback__', None).tb_lineno if getattr(e, '__traceback__', None) else 'unknown'
                }
            })

    return JsonResponse({'success': False, 'error': 'Método no permitido'}, status=405)

@csrf_exempt
@login_required
def stop_service(request):
    """Detener servicio de ingesta automática usando el servicio optimizado"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'Solo los superusuarios pueden gestionar servicios'}, status=403)
    
    if request.method == 'POST':
        try:
            from ids_ingest.services import ingest_service
            
            # Detener el servicio si está ejecutándose
            if ingest_service.running:
                ingest_service.stop()
                service_stopped = True
            else:
                service_stopped = False
            
            # Desactivar todas las configuraciones
            configs = IDSIngestConfig.objects.filter(active=True)
            count = configs.count()
            configs.update(active=False)
            
            message = f'{count} configuraciones desactivadas exitosamente'
            if service_stopped:
                message += ' y servicio detenido'
            
            return JsonResponse({
                'success': True,
                'message': message
            })
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': f'Error deteniendo servicio: {str(e)}'
            })
    
    return JsonResponse({'success': False, 'error': 'Método no permitido'}, status=405)

@csrf_exempt
@login_required
def start_daemon_service(request):
    """Iniciar servicio daemon de ingesta automática usando el servicio optimizado"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'Solo los superusuarios pueden gestionar servicios'}, status=403)
    
    if request.method == 'POST':
        try:
            from ids_ingest.services import ingest_service
            import subprocess
            import os
            
            # Verificar si el servicio ya está ejecutándose
            if ingest_service.running:
                return JsonResponse({
                    'success': False,
                    'error': 'El servicio de ingesta ya está ejecutándose'
                })
            
            # Intentar iniciar el daemon en background
            try:
                # En Windows, usar start para ejecutar en background
                if os.name == 'nt':
                    cmd = f'start /B python manage.py start_ingest_service --daemon --interval 60'
                    subprocess.Popen(cmd, shell=True, cwd=os.getcwd())
                else:
                    # En Linux/Mac, usar nohup
                    cmd = ['python', 'manage.py', 'start_ingest_service', '--daemon', '--interval', '60']
                    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                return JsonResponse({
                    'success': True,
                    'message': 'Servicio daemon iniciado en background. El servicio se ejecutará automáticamente cada 60 segundos con threading optimizado.'
                })
            except Exception as e:
                # Fallback: iniciar servicio directamente
                success = ingest_service.start(60)
                if success:
                    return JsonResponse({
                        'success': True,
                        'message': f'Servicio iniciado directamente. Error de background: {str(e)}'
                    })
                else:
                    return JsonResponse({
                        'success': False,
                        'error': f'No se pudo iniciar el servicio: {str(e)}'
                    })
                
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': f'Error iniciando daemon: {str(e)}'
            })
    
    return JsonResponse({'success': False, 'error': 'Método no permitido'}, status=405)

@csrf_exempt
@login_required
def get_service_status(request):
    """Obtener estado detallado del servicio usando el servicio optimizado"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'Solo los superusuarios pueden ver el estado'}, status=403)

    if request.method == 'POST':
        try:
            # Importar el servicio con manejo de errores
            try:
                from ids_ingest.services import ingest_service
                logger.info("✅ Servicio importado correctamente")
            except ImportError as e:
                logger.error(f"❌ Error importando servicio: {e}")
                return JsonResponse({
                    'success': False,
                    'error': f'Error importando servicio de ingesta: {str(e)}'
                })

            # Obtener estado del servicio optimizado
            try:
                service_status = ingest_service.get_status()
                logger.info(f"✅ Estado del servicio obtenido: {service_status}")
            except Exception as e:
                logger.error(f"❌ Error obteniendo estado del servicio: {e}")
                # Retornar estado por defecto si hay error
                service_status = {
                    'running': False,
                    'active_threads': 0,
                    'total_threads': 0,
                    'stats': {'total_processed': 0, 'total_errors': 0, 'last_run': None, 'active_configs': 0},
                    'queues': {}
                }

            # Obtener estadísticas adicionales
            try:
                configs = IDSIngestConfig.objects.all()
                active_configs = configs.filter(active=True).count()
                total_configs = configs.count()
                logger.info(f"✅ Estadísticas de configuraciones obtenidas: {total_configs} total, {active_configs} activas")
            except Exception as e:
                logger.error(f"❌ Error obteniendo configuraciones: {e}")
                configs = []
                active_configs = 0
                total_configs = 0

            # Logs recientes
            try:
                recent_snort = SnortLog.objects.filter(
                    timestamp__gte=timezone.now() - timedelta(hours=24)
                ).count()

                recent_suricata = SuricataEveAlert.objects.filter(
                    timestamp__gte=timezone.now() - timedelta(hours=24)
                ).count()
                logger.info(f"✅ Logs recientes obtenidos: Snort={recent_snort}, Suricata={recent_suricata}")
            except Exception as e:
                logger.error(f"❌ Error obteniendo logs recientes: {e}")
                recent_snort = 0
                recent_suricata = 0

            # Configuraciones obsoletas
            try:
                stale_configs = configs.filter(
                    active=True,
                    last_run__lt=timezone.now() - timedelta(hours=1)
                ).values_list('id', flat=True)
                logger.info(f"✅ Configuraciones obsoletas obtenidas: {list(stale_configs)}")
            except Exception as e:
                logger.error(f"❌ Error obteniendo configuraciones obsoletas: {e}")
                stale_configs = []

            status = {
                'service_running': service_status.get('running', False),
                'active_threads': service_status.get('active_threads', 0),
                'total_threads': service_status.get('total_threads', 0),
                'service_stats': service_status.get('stats', {}),
                'queue_sizes': service_status.get('queues', {}),
                'total_configs': total_configs,
                'active_configs': active_configs,
                'inactive_configs': total_configs - active_configs,
                'recent_snort': recent_snort,
                'recent_suricata': recent_suricata,
                'recent_logs': recent_snort + recent_suricata,
                'stale_configs': list(stale_configs),
                'timestamp': timezone.now().isoformat(),
                'debug_info': {
                    'service_imported': True,
                    'configs_query_success': total_configs >= 0,
                    'logs_query_success': (recent_snort >= 0 and recent_suricata >= 0)
                }
            }

            logger.info(f"✅ Estado completo generado exitosamente: {status}")
            return JsonResponse({
                'success': True,
                'status': status
            })

        except Exception as e:
            logger.error(f"❌ Error general en get_service_status: {e}", exc_info=True)
            return JsonResponse({
                'success': False,
                'error': f'Error obteniendo estado del servicio: {str(e)}',
                'debug_info': {
                    'exception_type': type(e).__name__,
                    'line_number': getattr(e, '__traceback__', None).tb_lineno if getattr(e, '__traceback__', None) else 'unknown'
                }
            })

    return JsonResponse({'success': False, 'error': 'Método no permitido'}, status=405)

@login_required
def suricata_dashboard_api(request):
    """API endpoint para actualizaciones AJAX del dashboard de Suricata"""
    # Reutilizar la lógica de suricata_dashboard pero retornar solo los datos necesarios
    # Filtros
    log_type = request.GET.get('log_type', 'eve_alerts')
    time_range = request.GET.get('time_range', '5m')
    severity_filter = request.GET.get('severity', '')
    src_ip_filter = request.GET.get('src_ip', '')
    dst_ip_filter = request.GET.get('dst_ip', '')
    protocol_filter = request.GET.get('protocol', '')
    search_query = request.GET.get('search', '')
    
    # Rango de tiempo
    now = timezone.now()
    ranges = {
        '5m': now - timedelta(minutes=5),
        '10m': now - timedelta(minutes=10),
        '15m': now - timedelta(minutes=15),
        '30m': now - timedelta(minutes=30),
        '1h': now - timedelta(hours=1),
        '2h': now - timedelta(hours=2),
        '6h': now - timedelta(hours=6),
        '12h': now - timedelta(hours=12),
        '24h': now - timedelta(hours=24),
        '7d': now - timedelta(days=7),
        '14d': now - timedelta(days=14),
        '1m': now - timedelta(days=30),
        '3m': now - timedelta(days=90),
        '6m': now - timedelta(days=180),
        '1y': now - timedelta(days=365),
    }
    since = ranges.get(time_range, now - timedelta(minutes=5))
    
    # Obtener datos según el tipo de log seleccionado
    if log_type == 'eve_alerts':
        logs = SuricataEveAlert.objects.filter(event_type='alert', timestamp__gte=since)
        if severity_filter:
            severity_map = {'Critical': 1, 'High': 2, 'Medium': 3, 'Low': 4}
            logs = logs.filter(severity=severity_map.get(severity_filter, 1))
        if src_ip_filter:
            logs = logs.filter(src_ip__icontains=src_ip_filter)
        if dst_ip_filter:
            logs = logs.filter(dest_ip__icontains=dst_ip_filter)
        if protocol_filter:
            logs = logs.filter(proto=protocol_filter)
        if search_query:
            logs = logs.filter(
                Q(message__icontains=search_query) |
                Q(src_ip__icontains=search_query) |
                Q(dest_ip__icontains=search_query)
            )
        
        # Estadísticas para EVE alerts
        stats = {
            'total': SuricataEveAlert.objects.filter(event_type='alert').count(),
            'critical': SuricataEveAlert.objects.filter(event_type='alert', severity=1).count(),
            'high': SuricataEveAlert.objects.filter(event_type='alert', severity=2).count(),
            'medium': SuricataEveAlert.objects.filter(event_type='alert', severity=3).count(),
            'low': SuricataEveAlert.objects.filter(event_type='alert', severity=4).count(),
            'last_24h': SuricataEveAlert.objects.filter(
                event_type='alert',
                timestamp__gte=timezone.now() - timedelta(hours=24)
            ).count(),
        }
        
    elif log_type == 'eve_flows':
        logs = SuricataFlow.objects.filter(timestamp__gte=since)
        if src_ip_filter:
            logs = logs.filter(src_ip__icontains=src_ip_filter)
        if dst_ip_filter:
            logs = logs.filter(dest_ip__icontains=dst_ip_filter)
        if protocol_filter:
            logs = logs.filter(proto=protocol_filter)
        if search_query:
            logs = logs.filter(
                Q(src_ip__icontains=search_query) |
                Q(dest_ip__icontains=search_query)
            )
        
        # Estadísticas para flows
        stats = {
            'total': SuricataFlow.objects.count(),
            'last_24h': SuricataFlow.objects.filter(
                timestamp__gte=timezone.now() - timedelta(hours=24)
            ).count(),
            'total_bytes': sum(SuricataFlow.objects.values_list('bytes_toserver', flat=True)) + 
                          sum(SuricataFlow.objects.values_list('bytes_toclient', flat=True)),
            'total_packets': sum(SuricataFlow.objects.values_list('pkts_toserver', flat=True)) + 
                            sum(SuricataFlow.objects.values_list('pkts_toclient', flat=True)),
        }
        
    elif log_type == 'fast_log':
        logs = SuricataLog.objects.filter(timestamp__gte=since)
        if severity_filter:
            logs = logs.filter(severity=severity_filter)
        if src_ip_filter:
            logs = logs.filter(src_ip__icontains=src_ip_filter)
        if dst_ip_filter:
            logs = logs.filter(dst_ip__icontains=dst_ip_filter)
        if protocol_filter:
            logs = logs.filter(protocol=protocol_filter)
        if search_query:
            logs = logs.filter(
                Q(message__icontains=search_query) |
                Q(src_ip__icontains=search_query) |
                Q(dst_ip__icontains=search_query)
            )
        
        # Estadísticas para fast.log
        stats = {
            'total': SuricataLog.objects.count(),
            'critical': SuricataLog.objects.filter(severity='Critical').count(),
            'high': SuricataLog.objects.filter(severity='High').count(),
            'medium': SuricataLog.objects.filter(severity='Medium').count(),
            'low': SuricataLog.objects.filter(severity='Low').count(),
            'last_24h': SuricataLog.objects.filter(
                timestamp__gte=timezone.now() - timedelta(hours=24)
            ).count(),
        }
        
    elif log_type == 'stats':
        logs = SuricataStats.objects.filter(timestamp__gte=since)
        stats = {
            'total': SuricataStats.objects.count(),
            'last_24h': SuricataStats.objects.filter(
                timestamp__gte=timezone.now() - timedelta(hours=24)
            ).count(),
            'avg_packets_per_sec': SuricataStats.objects.aggregate(
                avg_packets=Avg('packets_per_second')
            )['avg_packets'] or 0,
            'avg_bytes_per_sec': SuricataStats.objects.aggregate(
                avg_bytes=Avg('bytes_per_second')
            )['avg_bytes'] or 0,
        }
        
    elif log_type == 'system_log':
        logs = SuricataSystemLog.objects.filter(timestamp__gte=since)
        level_filter = request.GET.get('level', '')
        if level_filter:
            logs = logs.filter(level=level_filter)
        if search_query:
            logs = logs.filter(
                Q(message__icontains=search_query) |
                Q(component__icontains=search_query)
            )
        
        # Estadísticas para system log
        stats = {
            'total': SuricataSystemLog.objects.count(),
            'last_24h': SuricataSystemLog.objects.filter(
                timestamp__gte=timezone.now() - timedelta(hours=24)
            ).count(),
            'errors': SuricataSystemLog.objects.filter(level='ERROR').count(),
            'warnings': SuricataSystemLog.objects.filter(level='WARNING').count(),
        }
    
    # Paginación
    paginator = Paginator(logs.order_by('-timestamp'), 50)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    # Preparar datos para respuesta JSON
    logs_data = []
    for log in page_obj:
        if log_type == 'eve_alerts':
            logs_data.append({
                'id': log.id,
                'timestamp': log.timestamp.strftime('%d/%m/%Y %H:%M:%S'),
                'severity': log.severity,
                'src_ip': log.src_ip,
                'dest_ip': log.dest_ip,
                'proto': log.proto,
                'signature_id': log.signature_id,
                'message': log.message,
                'category': log.category,
            })
        elif log_type == 'eve_flows':
            logs_data.append({
                'id': log.id,
                'timestamp': log.timestamp.strftime('%d/%m/%Y %H:%M:%S'),
                'src_ip': log.src_ip,
                'dest_ip': log.dest_ip,
                'src_port': log.src_port,
                'dest_port': log.dest_port,
                'proto': log.proto,
                'app_proto': log.app_proto,
                'state': log.state,
                'pkts_toserver': log.pkts_toserver,
                'pkts_toclient': log.pkts_toclient,
                'bytes_toserver': log.bytes_toserver,
                'bytes_toclient': log.bytes_toclient,
                'age': log.age,
            })
        # Agregar más tipos según sea necesario
    
    return JsonResponse({
        'success': True,
        'stats': stats,
        'logs': logs_data,
        'total_count': paginator.count,
        'has_next': page_obj.has_next(),
        'has_previous': page_obj.has_previous(),
        'current_page': page_obj.number,
        'total_pages': paginator.num_pages,
    })

@login_required
def snort_log_details(request, log_id):
    """Obtener detalles completos de un log de Snort"""
    try:
        log = get_object_or_404(SnortLog, id=log_id)
        
        # Preparar datos del log
        log_data = {
            'id': log.id,
            'timestamp': log.timestamp.strftime('%d/%m/%Y %H:%M:%S'),
            'severity': log.severity,
            'priority': log.priority,
            'src_ip': log.src_ip,
            'dst_ip': log.dst_ip,
            'src_port': log.src_port,
            'dst_port': log.dst_port,
            'protocol': log.protocol,
            'message': log.message,
            'gid': log.gid,
            'sid': log.sid,
            'rev': log.rev,
            'classification': log.classification,
            'ttl': log.ttl,
            'tos': log.tos,
            'packet_id': log.packet_id,
            'ip_len': log.ip_len,
            'dgm_len': log.dgm_len,
            'flags': log.flags,
            'seq': log.seq,
            'ack': log.ack,
            'win': log.win,
            'tcp_len': log.tcp_len,
            'raw': log.raw,
            'created_at': log.created_at.strftime('%d/%m/%Y %H:%M:%S')
        }
        
        return JsonResponse({
            'success': True,
            'log': log_data
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Error obteniendo detalles: {str(e)}'
        })

@login_required
def run_log_rotation(request):
    """Ejecutar comando de rotación de logs"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No autorizado'})
    
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Método no permitido'})
    
    try:
        import json
        from django.core.management import call_command
        from io import StringIO
        
        data = json.loads(request.body)
        options = data.get('options', '')
        
        # Capturar salida del comando
        output = StringIO()
        
        # Ejecutar comando de rotación
        if options:
            call_command('rotate_suricata_logs', options, stdout=output)
        else:
            call_command('rotate_suricata_logs', stdout=output)
        
        result = output.getvalue()
        
        return JsonResponse({
            'success': True,
            'message': f'Rotación ejecutada correctamente:\n{result}'
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Error ejecutando rotación: {str(e)}'
        })
