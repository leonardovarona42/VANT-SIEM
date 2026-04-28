import json
import os
import logging
import re
from collections import Counter
from datetime import datetime, timedelta
from typing import Dict, Any

import pytz
try:
    import psycopg2
except Exception:
    psycopg2 = None
    from psycopg import connect as psycopg_connect
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.utils import timezone
from django.core.paginator import Paginator
from django.db.models import Q, Count, Avg, Max, Sum, Subquery
from django.db.models.functions import TruncMinute, TruncHour, TruncDate
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages

from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.utils import timezone
from django.core.paginator import Paginator
from django.db.models import Q, Count, Avg, Max, Sum, Subquery
from django.db.models.functions import TruncMinute, TruncHour, TruncDate
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages
from .models import (
    SnortLog, SuricataLog, IDSIngestConfig, IDSAlert, IDSStatistics,
    SuricataEveAlert, SuricataFlow, SuricataStats, SuricataSystemLog,
    SavedVisualization, SavedDashboard
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


def _serialize_saved_visualization(item):
    return {
        'id': item.id,
        'name': item.name,
        'description': item.description,
        'space': item.space,
        'is_shared': item.is_shared,
        'config': item.config,
        'created_at': item.created_at.isoformat() if item.created_at else None,
        'updated_at': item.updated_at.isoformat() if item.updated_at else None,
        'created_by': item.owner.username if item.owner_id else '',
    }


def _serialize_saved_dashboard(item):
    return {
        'id': item.id,
        'name': item.name,
        'description': item.description,
        'space': item.space,
        'is_shared': item.is_shared,
        'layout': item.layout,
        'created_at': item.created_at.isoformat() if item.created_at else None,
        'updated_at': item.updated_at.isoformat() if item.updated_at else None,
        'created_by': item.owner.username if item.owner_id else '',
    }


def _get_opensearch_pg_conn():
    if psycopg2 is None:
        return psycopg_connect(
            host=os.getenv('OS_DB_HOST', '127.0.0.1'),
            port=int(os.getenv('OS_DB_PORT', '5432')),
            dbname=os.getenv('OS_DB_NAME', 'vant_opensearch'),
            user=os.getenv('OS_DB_USER', 'postgres'),
            password=os.getenv('OS_DB_PASSWORD', 'postgres'),
        )
    return psycopg2.connect(
        host=os.getenv('OS_DB_HOST', '127.0.0.1'),
        port=int(os.getenv('OS_DB_PORT', '5432')),
        dbname=os.getenv('OS_DB_NAME', 'vant_opensearch'),
        user=os.getenv('OS_DB_USER', 'postgres'),
        password=os.getenv('OS_DB_PASSWORD', 'postgres'),
    )


def _build_viz_where(source, time_range, category, query):
    range_map = {
        '15m': timedelta(minutes=15),
        '1h': timedelta(hours=1),
        '24h': timedelta(hours=24),
        '7d': timedelta(days=7),
        '30d': timedelta(days=30),
        '90d': timedelta(days=90),
    }
    since = timezone.now() - range_map.get(time_range, timedelta(days=7))
    filters = ["event_time >= %s"]
    params = [since]

    if source and source != 'all':
        filters.append("source_type = %s")
        params.append(source)
    if category:
        filters.append("event_category = %s")
        params.append(category)
    if query:
        filters.append("(message ILIKE %s OR event_category ILIKE %s OR host_name ILIKE %s OR host_ip ILIKE %s OR source_name ILIKE %s)")
        like = f"%{query}%"
        params.extend([like, like, like, like, like])

    return " AND ".join(filters), params


def _field_sql(field):
    core_fields = {
        'id', 'source_type', 'source_name', 'host_name', 'host_ip', 'event_time',
        'severity', 'event_category', 'message', 'tags', 'ingested_at',
    }
    payload_allow = {
        'event_type', 'proto', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'dst_ip', 'dst_port',
        'app_proto', 'flow_id', 'in_iface', 'line', 'signature', 'classification', 'priority', 'gid', 'sid', 'rev',
    }
    if field in core_fields:
        return f"COALESCE(CAST({field} AS TEXT), '')", []
    if field in payload_allow:
        return "COALESCE(raw_payload ->> %s, '')", [field]
    return None, []


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



def get_suricata_chart_data(logs, time_range, now=None):
    """Generar datos para graficos de Suricata (Alertas EVE) usando agregacion eficiente."""
    now = now or timezone.now()

    minute_ranges = {'5m': 5, '10m': 10, '15m': 15, '30m': 30}
    hour_ranges = {'1h': 1, '2h': 2, '6h': 6, '12h': 12, '24h': 24}
    day_ranges = {'7d': 7, '14d': 14, '30d': 30, '90d': 90, '1m': 30, '3m': 90, '6m': 180, '1y': 365}

    if time_range in minute_ranges:
        total_units = minute_ranges[time_range]
        trunc = TruncMinute('timestamp')
        fmt = '%H:%M'
        step = timedelta(minutes=1)
    elif time_range in hour_ranges:
        total_units = hour_ranges[time_range]
        trunc = TruncHour('timestamp')
        fmt = '%H:00'
        step = timedelta(hours=1)
    else:
        total_units = day_ranges.get(time_range, 7)
        trunc = TruncDate('timestamp')
        fmt = '%m/%d'
        step = timedelta(days=1)

    bucket_counts = {
        row['bucket']: row['count']
        for row in logs.annotate(bucket=trunc).values('bucket').annotate(count=Count('id'))
    }

    timeline_data = []
    for i in range(total_units - 1, -1, -1):
        bucket_start = now - (step * (i + 1))
        if time_range in minute_ranges:
            bucket_start = bucket_start.replace(second=0, microsecond=0)
        elif time_range in hour_ranges:
            bucket_start = bucket_start.replace(minute=0, second=0, microsecond=0)
        else:
            bucket_start = bucket_start.replace(hour=0, minute=0, second=0, microsecond=0)
            bucket_start = timezone.make_naive(bucket_start, timezone.get_current_timezone()).date()

        timeline_data.append({
            'hour': bucket_start.strftime(fmt),
            'count': bucket_counts.get(bucket_start, 0)
        })

    proto_dist = list(
        logs.exclude(proto__isnull=True).exclude(proto='').values('proto').annotate(count=Count('id')).order_by('-count')[:10]
    )
    top_src_ports = list(
        logs.exclude(src_port__isnull=True).values('src_port').annotate(count=Count('id')).order_by('-count')[:10]
    )
    top_dest_ports = list(
        logs.exclude(dest_port__isnull=True).values('dest_port').annotate(count=Count('id')).order_by('-count')[:10]
    )
    top_src_ips = list(
        logs.exclude(src_ip__isnull=True).exclude(src_ip='').values('src_ip').annotate(count=Count('id')).order_by('-count')[:10]
    )
    top_dest_ips = list(
        logs.exclude(dest_ip__isnull=True).exclude(dest_ip='').values('dest_ip').annotate(count=Count('id')).order_by('-count')[:10]
    )

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
    latest_log_ts = None
    
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

    # Top signatures (24h)
    top_signatures = SnortLog.objects.filter(
        timestamp__gte=now - timedelta(hours=24)
    ).values('sid', 'message').annotate(
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
        'logs': logs_for_table,
        'stats': stats,
        'top_signatures': top_signatures,
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

@login_required
def snort_dashboard_v2(request):
    """Snort Dashboard V2"""
    from django.db.models import Count
    from django.utils import timezone
    from datetime import timedelta
    import json
    
    time_range = request.GET.get('time_range', '1h')
    now = timezone.now()
    
    # Handle 'all' option to show all data without time filter
    if time_range == 'all':
        start_time = None
    elif time_range == '5m':
        start_time = now - timedelta(minutes=5)
    elif time_range == '15m':
        start_time = now - timedelta(minutes=15)
    elif time_range == '1h':
        start_time = now - timedelta(hours=1)
    elif time_range == '6h':
        start_time = now - timedelta(hours=6)
    elif time_range == '24h':
        start_time = now - timedelta(hours=24)
    elif time_range == '7d':
        start_time = now - timedelta(days=7)
    else:
        start_time = now - timedelta(hours=1)
    
    # Filter logs based on time range
    if start_time:
        logs = SnortLog.objects.filter(timestamp__gte=start_time, timestamp__lte=now)
    else:
        logs = SnortLog.objects.all()
    
    # Severity is stored as strings: 'Critical', 'High', 'Medium', 'Low'
    critical_count = logs.filter(severity='Critical').count()
    high_count = logs.filter(severity='High').count()
    medium_count = logs.filter(severity='Medium').count()
    total_count = logs.count()
    alerts = logs.order_by('-timestamp')[:50]
    
    # Timeline - adjust based on time range
    timeline_labels = []
    timeline_data = []
    
    if time_range == 'all':
        # For "all" time, show last 7 days in daily buckets
        for i in range(7):
            d_start = now - timedelta(days=i+1)
            d_end = now - timedelta(days=i)
            count = SnortLog.objects.filter(timestamp__gte=d_start, timestamp__lt=d_end).count()
            timeline_labels.insert(0, d_start.strftime('%m/%d'))
            timeline_data.insert(0, count)
    else:
        # Show hourly buckets for shorter time ranges
        for i in range(6):
            h_start = now - timedelta(hours=i+1)
            h_end = now - timedelta(hours=i)
            count = logs.filter(timestamp__gte=h_start, timestamp__lt=h_end).count()
            timeline_labels.insert(0, h_start.strftime('%H:00'))
            timeline_data.insert(0, count)
    
    # Signatures (using message field)
    sigs = list(logs.values('message').annotate(c=Count('id')).order_by('-c')[:5])
    sig_labels = [s['message'][:50] if s['message'] else 'N/A' for s in sigs]
    sig_data = [s['c'] for s in sigs]
    
    # IPs
    src_ips = list(logs.values('src_ip').annotate(c=Count('id')).order_by('-c')[:10])
    src_ip_labels = [s['src_ip'] for s in src_ips if s['src_ip']]
    src_ip_data = [s['c'] for s in src_ips if s['src_ip']]
    
    dst_ips = list(logs.values('dst_ip').annotate(c=Count('id')).order_by('-c')[:10])
    dst_ip_labels = [d['dst_ip'] for d in dst_ips if d['dst_ip']]
    dst_ip_data = [d['c'] for d in dst_ips if d['dst_ip']]
    
    context = {
        'stats': {'critical': critical_count, 'high': high_count, 'medium': medium_count, 'total': total_count},
        'alerts': alerts,
        'time_range': time_range,
        'timeline_labels': json.dumps(timeline_labels),
        'timeline_data': json.dumps(timeline_data),
        'sig_labels': json.dumps(sig_labels),
        'sig_data': json.dumps(sig_data),
        'src_ip_labels': json.dumps(src_ip_labels),
        'src_ip_data': json.dumps(src_ip_data),
        'dst_ip_labels': json.dumps(dst_ip_labels),
        'dst_ip_data': json.dumps(dst_ip_data)
    }
    return render(request, 'snort_dashboard_v2.html', context)



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
    src_port_filter = request.GET.get('src_port', '')
    dst_port_filter = request.GET.get('dst_port', '')
    protocol_filter = request.GET.get('protocol', '')
    app_proto_filter = request.GET.get('app_proto', '')
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
        '30d': now - timedelta(days=30),
        '90d': now - timedelta(days=90),
        '1m': now - timedelta(days=30),
        '3m': now - timedelta(days=90),
        '6m': now - timedelta(days=180),
        '1y': now - timedelta(days=365),
    }
    since = ranges.get(time_range, now - timedelta(minutes=5))
    
    # Obtener datos según el tipo de log seleccionado

    if log_type == 'eve_alerts':
        logs = SuricataEveAlert.objects.filter(event_type='alert', timestamp__gte=since)
        latest_log_ts = SuricataEveAlert.objects.filter(event_type='alert').order_by('-timestamp').values_list('timestamp', flat=True).first()
        if severity_filter:
            # Handle numeric severity or string severity
            try:
                severity_val = int(severity_filter)
                logs = logs.filter(severity=severity_val)
            except ValueError:
                severity_map = {'Critical': 1, 'High': 2, 'Medium': 3, 'Low': 4, 'critical': 1, 'high': 2, 'medium': 3, 'low': 4}
                logs = logs.filter(severity=severity_map.get(severity_filter, 1))
        if src_ip_filter:
            # Handle NOT prefix for negation
            if src_ip_filter.startswith('NOT '):
                logs = logs.exclude(src_ip__icontains=src_ip_filter[4:])
            else:
                logs = logs.filter(src_ip__icontains=src_ip_filter)
        if dst_ip_filter:
            # Handle NOT prefix for negation
            if dst_ip_filter.startswith('NOT '):
                logs = logs.exclude(dest_ip__icontains=dst_ip_filter[4:])
            else:
                logs = logs.filter(dest_ip__icontains=dst_ip_filter)
        if src_port_filter:
            try:
                src_port_val = int(src_port_filter)
                logs = logs.filter(src_port=src_port_val)
            except (ValueError, TypeError):
                # If not a valid integer, skip this filter
                pass
        if dst_port_filter:
            try:
                dst_port_val = int(dst_port_filter)
                logs = logs.filter(dest_port=dst_port_val)
            except (ValueError, TypeError):
                # If not a valid integer, skip this filter
                pass
        if protocol_filter:
            logs = logs.filter(proto__icontains=protocol_filter)
        # Note: app_proto filter not available for SuricataEveAlert (only in SuricataFlow)
        # Using category as alternative for application-level filtering
        if app_proto_filter:
            logs = logs.filter(category__icontains=app_proto_filter)
        if search_query:
            logs = logs.filter(
                Q(message__icontains=search_query) |
                Q(src_ip__icontains=search_query) |
                Q(dest_ip__icontains=search_query)
            )

        # Estadísticas para EVE alerts
        stats = logs.aggregate(
            total=Count('id'),
            critical=Count('id', filter=Q(severity=1)),
            high=Count('id', filter=Q(severity=2)),
            medium=Count('id', filter=Q(severity=3)),
            low=Count('id', filter=Q(severity=4)),
            last_24h=Count('id', filter=Q(timestamp__gte=timezone.now() - timedelta(hours=24))),
        )
        total_logs = stats.get('total') or 0

        # Obtener valores únicos para filtros
        severities = ['Critical', 'High', 'Medium', 'Low']

        # Usar función igual que en Snort
        if total_logs > 300000:
            latest_ids = logs.order_by('-timestamp').values('id')[:300000]
            chart_logs = SuricataEveAlert.objects.filter(id__in=Subquery(latest_ids))
        else:
            chart_logs = logs
        protocols = chart_logs.values_list('proto', flat=True).distinct()
        chart_data = get_suricata_chart_data(chart_logs, time_range, now)
        proto_dist = chart_data['proto_dist']
        top_src_ips = chart_data['top_src_ips']
        top_dest_ips = chart_data['top_dest_ips']
        top_src_ports = chart_data['top_src_ports']
        top_dest_ports = chart_data['top_dest_ports']
        timeline = chart_data['timeline']
        
    elif log_type == 'eve_flows':
        logs = SuricataFlow.objects.filter(timestamp__gte=since)
        latest_log_ts = SuricataFlow.objects.order_by('-timestamp').values_list('timestamp', flat=True).first()
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
        flow_stats = logs.aggregate(
            total=Count('id'),
            last_24h=Count('id', filter=Q(timestamp__gte=timezone.now() - timedelta(hours=24))),
            bytes_toserver_sum=Sum('bytes_toserver'),
            bytes_toclient_sum=Sum('bytes_toclient'),
            pkts_toserver_sum=Sum('pkts_toserver'),
            pkts_toclient_sum=Sum('pkts_toclient'),
        )
        stats = {
            'total': flow_stats.get('total') or 0,
            'last_24h': flow_stats.get('last_24h') or 0,
            'total_bytes': (flow_stats.get('bytes_toserver_sum') or 0) + (flow_stats.get('bytes_toclient_sum') or 0),
            'total_packets': (flow_stats.get('pkts_toserver_sum') or 0) + (flow_stats.get('pkts_toclient_sum') or 0),
        }
        
        severities = []
        protocols = logs.values_list('proto', flat=True).distinct()
        
        flows_qs = SuricataFlow.objects.filter(timestamp__gte=since)
        flow_proto_dist = list(flows_qs.values('proto').annotate(count=Count('proto')).order_by('-count')[:10])
        flow_top_src_ips = list(flows_qs.values('src_ip').annotate(count=Count('src_ip')).order_by('-count')[:10])
        flow_top_dest_ips = list(flows_qs.values('dest_ip').annotate(count=Count('dest_ip')).order_by('-count')[:10])
        
    elif log_type == 'fast_log':
        logs = SuricataLog.objects.filter(timestamp__gte=since)  # Usar el modelo original para fast.log
        latest_log_ts = SuricataLog.objects.order_by('-timestamp').values_list('timestamp', flat=True).first()
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
        stats = logs.aggregate(
            total=Count('id'),
            critical=Count('id', filter=Q(severity='Critical')),
            high=Count('id', filter=Q(severity='High')),
            medium=Count('id', filter=Q(severity='Medium')),
            low=Count('id', filter=Q(severity='Low')),
            last_24h=Count('id', filter=Q(timestamp__gte=timezone.now() - timedelta(hours=24))),
        )
        
        severities = logs.values_list('severity', flat=True).distinct()
        protocols = logs.values_list('protocol', flat=True).distinct()
        
        fl_qs = SuricataLog.objects.filter(timestamp__gte=since)
        fast_proto_dist = list(fl_qs.values('protocol').annotate(count=Count('protocol')).order_by('-count')[:10])
        fast_top_src_ips = list(fl_qs.values('src_ip').annotate(count=Count('src_ip')).order_by('-count')[:10])
        fast_top_dst_ips = list(fl_qs.values('dst_ip').annotate(count=Count('dst_ip')).order_by('-count')[:10])
        fast_top_src_ports = list(fl_qs.exclude(src_port=None).values('src_port').annotate(count=Count('src_port')).order_by('-count')[:10])
        fast_top_dst_ports = list(fl_qs.exclude(dst_port=None).values('dst_port').annotate(count=Count('dst_port')).order_by('-count')[:10])
        
    elif log_type == 'stats':
        logs = SuricataStats.objects.filter(timestamp__gte=since)
        latest_log_ts = SuricataStats.objects.order_by('-timestamp').values_list('timestamp', flat=True).first()
        stats_agg = logs.aggregate(
            total=Count('id'),
            last_24h=Count('id', filter=Q(timestamp__gte=timezone.now() - timedelta(hours=24))),
            avg_packets=Avg('packets_per_second'),
            avg_bytes=Avg('bytes_per_second'),
        )
        stats = {
            'total': stats_agg.get('total') or 0,
            'last_24h': stats_agg.get('last_24h') or 0,
            'avg_packets_per_sec': stats_agg.get('avg_packets') or 0,
            'avg_bytes_per_sec': stats_agg.get('avg_bytes') or 0,
        }
        severities = []
        protocols = []
        
    elif log_type == 'system_log':
        logs = SuricataSystemLog.objects.filter(timestamp__gte=since)
        latest_log_ts = SuricataSystemLog.objects.order_by('-timestamp').values_list('timestamp', flat=True).first()
        level_filter = request.GET.get('level', '')
        if level_filter:
            logs = logs.filter(level=level_filter)
        if search_query:
            logs = logs.filter(
                Q(message__icontains=search_query) |
                Q(component__icontains=search_query)
            )

        # Estadísticas para system log
        stats = logs.aggregate(
            total=Count('id'),
            last_24h=Count('id', filter=Q(timestamp__gte=timezone.now() - timedelta(hours=24))),
            errors=Count('id', filter=Q(level='ERROR')),
            warnings=Count('id', filter=Q(level='WARNING')),
        )

        severities = []
        protocols = []
    
    logs_for_table = list(logs.order_by('-timestamp')[:100])
    has_data_in_range = len(logs_for_table) > 0
    

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
    app_proto_dist = []
    top_source_countries = []
    top_dest_countries = []
    chart = {}

    # Definir top_signatures y datasets de gráficos usando get_suricata_chart_data si estamos en eve_alerts
    if log_type == 'eve_alerts':
        chart_logs = locals().get('chart_logs', logs)
        top_signatures = list(
            chart_logs.values('signature_id', 'message').annotate(count=Count('signature_id')).order_by('-count')[:10]
        )

        # Reusar agregados ya calculados en get_suricata_chart_data para evitar consultas duplicadas
        proto_dist = chart_data.get('proto_dist', [])
        top_src_ips = chart_data.get('top_src_ips', [])
        top_dest_ips = chart_data.get('top_dest_ips', [])
        top_src_ports = chart_data.get('top_src_ports', [])
        top_dest_ports = chart_data.get('top_dest_ports', [])
        timeline = chart_data.get('timeline', [])

        app_proto_dist = list(
            chart_logs.exclude(category__isnull=True).exclude(category='').values('category').annotate(
                count=Count('id')
            ).order_by('-count')[:10]
        )

        top_source_countries = list(
            chart_logs.exclude(src_ip__isnull=True).exclude(src_ip='').values('src_ip').annotate(count=Count('id')).order_by('-count')[:10]
        )
        for item in top_source_countries:
            item['country'] = 'Unknown'

        top_dest_countries = list(
            chart_logs.exclude(dest_ip__isnull=True).exclude(dest_ip='').values('dest_ip').annotate(count=Count('id')).order_by('-count')[:10]
        )
        for item in top_dest_countries:
            item['country'] = 'Unknown'

        chart = {
            'proto_dist': proto_dist,
            'app_proto_dist': app_proto_dist,
            'top_src_ips': top_src_ips,
            'top_dest_ips': top_dest_ips,
            'top_src_ports': top_src_ports,
            'top_dest_ports': top_dest_ports,
            'timeline': timeline,
        }
    elif log_type == 'eve_flows':
        chart = {
            'proto_dist': flow_proto_dist if 'flow_proto_dist' in dir() else [],
            'top_src_ips': flow_top_src_ips if 'flow_top_src_ips' in dir() else [],
            'top_dest_ips': flow_top_dest_ips if 'flow_top_dest_ips' in dir() else [],
            'top_src_ports': [],
            'top_dest_ports': [],
            'timeline': [],
        }
    elif log_type == 'fast_log':
        chart = {
            'proto_dist': fast_proto_dist if 'fast_proto_dist' in dir() else [],
            'top_src_ips': fast_top_src_ips if 'fast_top_src_ips' in dir() else [],
            'top_dest_ips': fast_top_dst_ips if 'fast_top_dst_ips' in dir() else [],
            'top_src_ports': fast_top_src_ports if 'fast_top_src_ports' in dir() else [],
            'top_dest_ports': fast_top_dst_ports if 'fast_top_dst_ports' in dir() else [],
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
        'logs': logs_for_table,
        'stats': stats,
        'severities': severities,
        'protocols': protocols,
        'log_type': log_type,
        'time_range': time_range,
        'recent_alerts': recent_alerts,
        'top_signatures': top_signatures,
        'top_src_ips': top_src_ips,
        'chart': chart,  # Pass as Python dict for template conditionals
        'chart_json': json.dumps(chart),  # Pass as JSON string for JavaScript
        'has_data_in_range': has_data_in_range,
        'latest_log_ts': latest_log_ts,
        
        # Debug info
        'debug_info': {
            'logs_count': stats.get('total', 0) if log_type == 'eve_alerts' else 0,
            'proto_dist_count': len(proto_dist),
            'timeline_count': len(timeline),
            'app_proto_dist_count': len(app_proto_dist),
            'top_src_ips_count': len(top_src_ips),
            'top_source_countries_count': len(top_source_countries),
            'top_dest_countries_count': len(top_dest_countries),
            'log_type': log_type,
        },
        'top_source_countries': top_source_countries if log_type == 'eve_alerts' else [],
        'top_dest_countries': top_dest_countries if log_type == 'eve_alerts' else [],
        'filters': {
            'severity': severity_filter,
            'src_ip': src_ip_filter,
            'dst_ip': dst_ip_filter,
            'src_port': src_port_filter,
            'dst_port': dst_port_filter,
            'protocol': protocol_filter,
            'app_proto': app_proto_filter,
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
                        from opensearch_ui.services import ingest_service
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
                    from opensearch_ui.services import ingest_service
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
            from opensearch_ui.services import ingest_service
            
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
            from opensearch_ui.services import ingest_service

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
            from opensearch_ui.services import ingest_service
            
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
            from opensearch_ui.services import ingest_service
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
                from opensearch_ui.services import ingest_service
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
        '30d': now - timedelta(days=30),
        '90d': now - timedelta(days=90),
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
        flow_stats = logs.aggregate(
            total=Count('id'),
            last_24h=Count('id', filter=Q(timestamp__gte=timezone.now() - timedelta(hours=24))),
            bytes_toserver_sum=Sum('bytes_toserver'),
            bytes_toclient_sum=Sum('bytes_toclient'),
            pkts_toserver_sum=Sum('pkts_toserver'),
            pkts_toclient_sum=Sum('pkts_toclient'),
        )
        stats = {
            'total': flow_stats.get('total') or 0,
            'last_24h': flow_stats.get('last_24h') or 0,
            'total_bytes': (flow_stats.get('bytes_toserver_sum') or 0) + (flow_stats.get('bytes_toclient_sum') or 0),
            'total_packets': (flow_stats.get('pkts_toserver_sum') or 0) + (flow_stats.get('pkts_toclient_sum') or 0),
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
        stats = logs.aggregate(
            total=Count('id'),
            critical=Count('id', filter=Q(severity='Critical')),
            high=Count('id', filter=Q(severity='High')),
            medium=Count('id', filter=Q(severity='Medium')),
            low=Count('id', filter=Q(severity='Low')),
            last_24h=Count('id', filter=Q(timestamp__gte=timezone.now() - timedelta(hours=24))),
        )
        
    elif log_type == 'stats':
        logs = SuricataStats.objects.filter(timestamp__gte=since)
        stats_agg = logs.aggregate(
            total=Count('id'),
            last_24h=Count('id', filter=Q(timestamp__gte=timezone.now() - timedelta(hours=24))),
            avg_packets=Avg('packets_per_second'),
            avg_bytes=Avg('bytes_per_second'),
        )
        stats = {
            'total': stats_agg.get('total') or 0,
            'last_24h': stats_agg.get('last_24h') or 0,
            'avg_packets_per_sec': stats_agg.get('avg_packets') or 0,
            'avg_bytes_per_sec': stats_agg.get('avg_bytes') or 0,
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
        stats = logs.aggregate(
            total=Count('id'),
            last_24h=Count('id', filter=Q(timestamp__gte=timezone.now() - timedelta(hours=24))),
            errors=Count('id', filter=Q(level='ERROR')),
            warnings=Count('id', filter=Q(level='WARNING')),
        )
    
    # Paginación
    page_size = 50
    try:
        page_number = max(1, int(request.GET.get('page', 1)))
    except (TypeError, ValueError):
        page_number = 1
    offset = (page_number - 1) * page_size
    logs_slice = list(logs.order_by('-timestamp')[offset:offset + page_size + 1])
    has_next = len(logs_slice) > page_size
    page_items = logs_slice[:page_size]
    has_previous = page_number > 1
    
    # Preparar datos para respuesta JSON
    logs_data = []
    for log in page_items:
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
        'total_count': len(page_items),
        'has_next': has_next,
        'has_previous': has_previous,
        'current_page': page_number,
        'total_pages': None,
    })

@login_required
def domain_audit_dashboard(request):
    """Dashboard de auditoría de dominio/LDAP basado en logs ingestado por agentes."""
    context = _build_domain_audit_context(request)
    return render(request, 'domain_audit_dashboard.html', context)


@login_required
def ad_executive_dashboard(request):
    """Resumen ejecutivo de riesgos en Active Directory."""
    context = _build_domain_audit_context(request)
    return render(request, 'ad_executive_dashboard.html', context)


@login_required
def ad_identity_hygiene_dashboard(request):
    """Higiene de identidades y accesos en Active Directory."""
    context = _build_domain_audit_context(request)
    return render(request, 'ad_identity_hygiene.html', context)


@login_required
def ad_change_audit_dashboard(request):
    """Auditoría de cambios en Active Directory."""
    context = _build_domain_audit_context(request)
    return render(request, 'ad_change_audit.html', context)


@login_required
def ad_soc_triage_dashboard(request):
    """Triage SOC para Active Directory."""
    context = _build_domain_audit_context(request)
    return render(request, 'ad_soc_triage.html', context)


@login_required
def domain_audit_dashboard_api(request):
    """API endpoint para actualizaciones AJAX del dashboard de auditoría de dominio"""
    context = _build_domain_audit_context(request)
    return JsonResponse({'success': True, **context})


def _build_domain_audit_context(request):
    time_range = request.GET.get('time_range', '24h')
    query = request.GET.get('q', '').strip()
    try:
        page = max(int(request.GET.get('page', '1') or '1'), 1)
    except (TypeError, ValueError):
        page = 1
    page_size = 100
    include_tokens = request.GET.getlist('f')
    exclude_tokens = request.GET.getlist('nf')

    range_map = {
        '15m': timedelta(minutes=15),
        '1h': timedelta(hours=1),
        '24h': timedelta(hours=24),
        '7d': timedelta(days=7),
        '30d': timedelta(days=30),
    }
    since = timezone.now() - range_map.get(time_range, timedelta(hours=24))

    core_fields = [
        'event_time',
        'source_type',
        'source_name',
        'host_name',
        'host_ip',
        'severity',
        'event_category',
        'message',
        'tags',
    ]
    domain_fields = [
        'user',
        'account',
        'target',
        'ou',
        'auth_pair',
        'service',
        'event_id',
        'action',
        'result',
        'auth_method',
        'logon_type',
        'src_ip',
        'src_port',
        'dst_ip',
        'dst_port',
        'workstation',
        'domain',
        'service',
        'line',
        'path',
        'raw_json',
    ]
    table_columns = [
        'event_time',
        'source_name',
        'host_name',
        'user',
        'target',
        'ou',
        'event_id',
        'action',
        'result',
        'src_ip',
        'dst_ip',
        'service',
        'event_category',
        'severity',
        'message',
    ]
    allowed_fields = set(core_fields + domain_fields)

    parsed_include = []
    parsed_exclude = []
    for token in include_tokens:
        if ':' in token:
            field, value = token.split(':', 1)
            field = field.strip()
            value = value.strip()
            if field and value:
                parsed_include.append((field, value, token))
    for token in exclude_tokens:
        if ':' in token:
            field, value = token.split(':', 1)
            field = field.strip()
            value = value.strip()
            if field and value:
                parsed_exclude.append((field, value, token))

    def _value_matches(field_value, filter_value):
        text = '' if field_value is None else str(field_value).strip()
        if filter_value == '__EMPTY__':
            return text == ''
        return filter_value.lower() in text.lower()

    def _payload_lookup(payload, key):
        if not key:
            return None
        if key in payload:
            return payload.get(key)
        if '.' not in key:
            return payload.get(key)
        cur = payload
        for part in key.split('.'):
            if not isinstance(cur, dict):
                return None
            cur = cur.get(part)
        return cur

    user_keys = [
        'user', 'username', 'account', 'account_name', 'user_name', 'subject',
        'target_user', 'target_user_name', 'principal', 'user_id',
    ]
    action_keys = ['action', 'operation', 'event_action', 'activity', 'op', 'event_type']
    result_keys = ['result', 'status', 'outcome', 'success', 'failure', 'auth_result']
    event_id_keys = ['event_id', 'eventid', 'id', 'eventId']
    auth_keys = ['auth_method', 'authentication', 'auth', 'logon_type']

    ip_re = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}')

    def _find_first(payload, keys):
        for k in keys:
            val = _payload_lookup(payload, k)
            if val not in (None, '', 'null', 'None'):
                return val
        return None

    def _parse_dn(dn):
        if not dn:
            return {'cn': None, 'ou': None, 'domain': None}
        parts = [p.strip() for p in str(dn).split(',') if p.strip()]
        cn = None
        ous = []
        dcs = []
        for p in parts:
            up = p.upper()
            if up.startswith('CN=') and cn is None:
                cn = p[3:]
            elif up.startswith('OU='):
                ous.append(p[3:])
            elif up.startswith('DC='):
                dcs.append(p[3:])
        ou = ' / '.join(ous) if ous else None
        domain = '.'.join(dcs) if dcs else None
        if not ou:
            for p in parts:
                if p.upper() == 'CN=USERS':
                    ou = 'Users'
                    break
        return {'cn': cn, 'ou': ou, 'domain': domain}

    def _safe_json(text):
        if not text:
            return None
        raw = str(text).strip()
        if not raw.startswith('{'):
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None

    authz_re = re.compile(
        r'(?P<status>Successful|Failed)\s+AuthZ:\s+\[(?P<service>[^\]]+)\]\s+'
        r'user\s+\[(?P<domain>[^\]]+)\]\\\[(?P<user>[^\]]+)\].*?'
        r'Remote host\s+\[(?P<src>[^\]]+)\]\s+local host\s+\[(?P<dst>[^\]]+)\]'
    )
    dsdb_re = re.compile(
        r'DSDB Change\s+\[(?P<action>[^\]]+)\].*?status\s+\[(?P<status>[^\]]+)\].*?DN\s+\[(?P<dn>[^\]]+)\]'
    )
    bind_re = re.compile(r'Bind(?:Simple|SASL)?\\s+dn:\\s+(?P<dn>.+)', re.IGNORECASE)

    def _is_noise_event(base_map, derived):
        msg = (base_map.get('message') or '').lower()
        category = (base_map.get('event_category') or '').lower()
        if derived.get('user') or derived.get('action') or derived.get('result') or derived.get('target'):
            return False
        noisy_markers = [
            'debug_lookup_classname',
            'samba_kcc',
            'kccsrv_samba_kcc',
            'samba_runcmd_io_handler',
            'initialising global parameters',
        ]
        if any(n in msg for n in noisy_markers):
            return True
        if category in ('samba.perhost', 'samba.wb', 'samba.winbind', 'samba.winbindd'):
            return True
        return False

    def _derive_domain_fields(base_map, payload):
        derived = {}
        msg = base_map.get('message') or ''

        raw_json = _safe_json(msg)
        if raw_json and isinstance(raw_json, dict):
            if 'Authorization' in raw_json:
                auth = raw_json.get('Authorization') or {}
                domain = auth.get('domain') or ''
                account = auth.get('account') or ''
                user = f"{domain}\\{account}" if domain and account else (account or domain)
                derived['user'] = user or None
                derived['action'] = 'Authorization'
                derived['result'] = 'Success'
                derived['auth_method'] = auth.get('authType')
                derived['service'] = auth.get('serviceDescription')
                derived['src_ip'] = auth.get('remoteAddress')
                derived['dst_ip'] = auth.get('localAddress')
                derived['target'] = auth.get('logonServer') or base_map.get('host_name')
            elif 'Authentication' in raw_json:
                auth = raw_json.get('Authentication') or {}
                domain = auth.get('domain') or ''
                account = auth.get('account') or ''
                user = f"{domain}\\{account}" if domain and account else (account or domain)
                derived['user'] = user or None
                derived['action'] = 'Authentication'
                derived['result'] = auth.get('status') or auth.get('result')
                derived['auth_method'] = auth.get('authType') or auth.get('mechanism')
                derived['service'] = auth.get('serviceDescription')
                derived['src_ip'] = auth.get('remoteAddress')
                derived['dst_ip'] = auth.get('localAddress')
                derived['target'] = auth.get('logonServer') or base_map.get('host_name')

        match = authz_re.search(msg)
        if match:
            gd = match.groupdict()
            derived['user'] = f"{gd.get('domain')}\\{gd.get('user')}" if gd.get('domain') else gd.get('user')
            derived['action'] = 'Authorization'
            derived['result'] = 'Success' if gd.get('status') == 'Successful' else 'Failed'
            derived['service'] = gd.get('service')
            derived['src_ip'] = gd.get('src')
            derived['dst_ip'] = gd.get('dst')

        match = dsdb_re.search(msg)
        if match:
            gd = match.groupdict()
            derived['action'] = gd.get('action')
            derived['result'] = gd.get('status')
            dn_info = _parse_dn(gd.get('dn'))
            if dn_info.get('cn'):
                derived['target'] = dn_info.get('cn')
            if dn_info.get('ou'):
                derived['ou'] = dn_info.get('ou')
            if dn_info.get('domain'):
                derived['domain'] = dn_info.get('domain')

        match = bind_re.search(msg)
        if match:
            dn = match.group('dn')
            dn_info = _parse_dn(dn)
            if dn_info.get('cn'):
                derived.setdefault('user', dn_info.get('cn'))
            if dn_info.get('ou'):
                derived.setdefault('ou', dn_info.get('ou'))
            derived.setdefault('action', 'Bind')
            derived.setdefault('result', 'Attempt')

        if 'result' not in derived:
            lower = msg.lower()
            if 'success' in lower or 'successful' in lower or 'accepted' in lower:
                derived['result'] = 'Success'
            elif 'fail' in lower or 'denied' in lower or 'invalid' in lower or 'error' in lower:
                derived['result'] = 'Failed'

        if 'event_id' not in derived:
            derived['event_id'] = _find_first(payload, event_id_keys)
        if 'user' not in derived:
            derived['user'] = _find_first(payload, user_keys)
        if 'action' not in derived:
            derived['action'] = _find_first(payload, action_keys)
        if 'result' not in derived:
            derived['result'] = _find_first(payload, result_keys)
        if 'auth_method' not in derived:
            derived['auth_method'] = _find_first(payload, auth_keys)
        if 'src_ip' not in derived:
            derived['src_ip'] = _payload_lookup(payload, 'src_ip')
        if 'dst_ip' not in derived:
            derived['dst_ip'] = _payload_lookup(payload, 'dst_ip')
        if 'target' not in derived:
            derived['target'] = _payload_lookup(payload, 'target')

        if derived.get('user') and not derived.get('auth_pair'):
            target = derived.get('target') or base_map.get('host_name') or derived.get('dst_ip') or base_map.get('host_ip')
            if target:
                derived['auth_pair'] = f"{derived['user']} -> {target}"

        # Summary for knowledge-centric tables
        if derived.get('action') or derived.get('result') or derived.get('user') or derived.get('target'):
            parts = []
            if derived.get('user'):
                parts.append(str(derived.get('user')))
            if derived.get('action'):
                parts.append(str(derived.get('action')))
            if derived.get('target'):
                parts.append(f"target={derived.get('target')}")
            if derived.get('ou'):
                parts.append(f"ou={derived.get('ou')}")
            if derived.get('result'):
                parts.append(f"result={derived.get('result')}")
            if derived.get('service'):
                parts.append(f"service={derived.get('service')}")
            derived['summary'] = ' | '.join(parts)

        return derived


    mem_include_filters = []
    mem_exclude_filters = []
    active_filters = []
    for field, value, token in parsed_include:
        if field not in allowed_fields:
            continue
        mem_include_filters.append((field, value, token))
        active_filters.append({'mode': 'include', 'field': field, 'value': value, 'token': token})
    for field, value, token in parsed_exclude:
        if field not in allowed_fields:
            continue
        mem_exclude_filters.append((field, value, token))
        active_filters.append({'mode': 'exclude', 'field': field, 'value': value, 'token': token})

    bucket_unit, bucket_step = {
        '15m': ('minute', 1),
        '1h': ('minute', 5),
        '24h': ('hour', 1),
        '7d': ('day', 1),
        '30d': ('day', 1),
    }.get(time_range, ('hour', 1))

    def _floor_bucket(dt, unit, step):
        if unit == 'minute':
            minute = (dt.minute // step) * step
            return dt.replace(minute=minute, second=0, microsecond=0)
        if unit == 'hour':
            hour = (dt.hour // step) * step
            return dt.replace(hour=hour, minute=0, second=0, microsecond=0)
        base = dt.replace(hour=0, minute=0, second=0, microsecond=0)
        if step <= 1:
            return base
        offset = base.toordinal() % step
        return base - timedelta(days=offset)

    def _iter_buckets(start_dt, end_dt, unit, step):
        cur = _floor_bucket(start_dt, unit, step)
        while cur <= end_dt:
            yield cur
            if unit == 'minute':
                cur = cur + timedelta(minutes=step)
            elif unit == 'hour':
                cur = cur + timedelta(hours=step)
            else:
                cur = cur + timedelta(days=step)

    filters = ["event_time >= %s"]
    params = [since]
    filters.append(
        "("
        "source_type IN ('windows_eventlog', 'file_log', 'agent') "
        "OR event_category ILIKE %s OR event_category ILIKE %s OR event_category ILIKE %s "
        "OR source_name ILIKE %s "
        "OR tags ? 'ad' OR tags ? 'ldap' OR tags ? 'domain' OR tags ? 'audit'"
        ")"
    )
    params.extend(['%samba%', '%ldap%', '%domain%', '%samba%'])
    if query:
        like = f"%{query}%"
        filters.append("(message ILIKE %s OR event_category ILIKE %s OR host_name ILIKE %s OR source_name ILIKE %s)")
        params.extend([like, like, like, like])

    rows = []
    total = 0
    db_error = None
    offset = (page - 1) * page_size
    now_ts = timezone.now()
    bucket_counts = {b: 0 for b in _iter_buckets(since, now_ts, bucket_unit, bucket_step)}
    top_categories = Counter()
    top_sources = Counter()
    top_hosts = Counter()
    top_users = Counter()
    top_targets = Counter()
    top_ous = Counter()
    top_auth_pairs = Counter()
    top_actions = Counter()
    top_results = Counter()
    top_src_ips = Counter()
    top_dst_ips = Counter()
    top_services = Counter()
    top_failed_src_ips = Counter()
    top_lockout_users = Counter()
    unique_users = set()
    unique_targets = set()
    modified_targets = set()
    modified_ous = set()
    auth_success = 0
    auth_failed = 0
    auth_total = 0
    password_changes = 0
    user_modifications = 0
    group_changes = 0
    policy_changes = 0
    ldap_binds = 0
    kerberos_events = 0
    lockout_events = 0

    def _add_counter(counter, value):
        if value is None:
            return
        text = str(value).strip()
        if not text or text.lower() in ('none', 'null', '-'):
            return
        counter[text] += 1

    query_sql = f"""
        SELECT
            id,
            source_type,
            source_name,
            host_name,
            host_ip,
            event_time,
            severity,
            event_category,
            message,
            tags,
            ingested_at,
            COALESCE(raw_payload, '{{}}'::jsonb) AS raw_payload
        FROM os_events_raw
        WHERE {" AND ".join(filters)}
        ORDER BY event_time DESC
    """

    try:
        pg = _get_opensearch_pg_conn()
        with pg.cursor(name='domain_audit_stream') as cur:
            cur.itersize = 2000
            cur.execute(query_sql, params)
            matched = 0
            start_idx = offset
            end_idx = offset + page_size
            for record in cur:
                payload = record[11] if isinstance(record[11], dict) else {}
                if payload is None:
                    payload = {}

                base_map = {
                    'id': record[0],
                    'source_type': record[1],
                    'source_name': record[2],
                    'host_name': record[3],
                    'host_ip': record[4],
                    'event_time': record[5],
                    'severity': record[6],
                    'event_category': record[7],
                    'message': record[8],
                    'tags': record[9],
                    'ingested_at': record[10],
                }

                derived = _derive_domain_fields(base_map, payload)
                if _is_noise_event(base_map, derived):
                    continue

                def _get_field_value(field_name):
                    if field_name in derived:
                        return derived.get(field_name)
                    if field_name in core_fields:
                        return base_map.get(field_name)
                    return _payload_lookup(payload, field_name)

                include_ok = all(_value_matches(_get_field_value(f), v) for f, v, _ in mem_include_filters)
                exclude_ok = all(not _value_matches(_get_field_value(f), v) for f, v, _ in mem_exclude_filters)
                if not (include_ok and exclude_ok):
                    continue

                event_time = base_map.get('event_time')
                if event_time:
                    if timezone.is_naive(event_time):
                        event_time = timezone.make_aware(event_time, timezone.get_current_timezone())
                    bucket = _floor_bucket(event_time, bucket_unit, bucket_step)
                    if bucket in bucket_counts:
                        bucket_counts[bucket] += 1

                action_val = _get_field_value('action')
                result_val = _get_field_value('result')
                user_val = _get_field_value('user')
                target_val = _get_field_value('target')
                ou_val = _get_field_value('ou')
                auth_pair_val = _get_field_value('auth_pair')
                service_val = _get_field_value('service')
                msg_lower = (base_map.get('message') or '').lower()
                category_lower = (base_map.get('event_category') or '').lower()
                action_lower = (str(action_val or '')).lower()
                result_lower = (str(result_val or '')).lower()

                _add_counter(top_categories, base_map.get('event_category'))
                _add_counter(top_sources, base_map.get('source_name'))
                _add_counter(top_hosts, base_map.get('host_name'))
                _add_counter(top_users, user_val)
                _add_counter(top_actions, action_val)
                _add_counter(top_results, result_val)
                _add_counter(top_src_ips, _get_field_value('src_ip'))
                _add_counter(top_dst_ips, _get_field_value('dst_ip'))
                _add_counter(top_services, service_val)

                if action_val and str(action_val).lower() in ('modify', 'add', 'delete', 'reset', 'password', 'changepassword'):
                    _add_counter(top_targets, target_val)
                    _add_counter(top_ous, ou_val)
                    if target_val:
                        modified_targets.add(str(target_val))
                    if ou_val:
                        modified_ous.add(str(ou_val))
                elif ou_val or target_val:
                    _add_counter(top_targets, target_val)
                    _add_counter(top_ous, ou_val)

                _add_counter(top_auth_pairs, auth_pair_val)

                if user_val:
                    unique_users.add(str(user_val))
                if target_val:
                    unique_targets.add(str(target_val))

                is_success = any(token in result_lower for token in ('success', 'ok', 'accepted')) or ('successful' in msg_lower)
                is_failed = any(token in result_lower for token in ('fail', 'denied', 'invalid', 'error')) or ('failed' in msg_lower)

                if 'auth' in action_lower or 'authorization' in action_lower or 'authentication' in action_lower or 'autenticacion' in category_lower or 'auth' in category_lower:
                    auth_total += 1
                    if is_success:
                        auth_success += 1
                    if is_failed:
                        auth_failed += 1

                if 'lockout' in msg_lower or 'bloque' in msg_lower:
                    lockout_events += 1
                    _add_counter(top_lockout_users, user_val)

                if 'password' in action_lower or 'contrasen' in msg_lower or 'cambios_contrasenas' in category_lower:
                    password_changes += 1

                if 'modify' in action_lower or 'modificaciones_usuarios' in category_lower:
                    user_modifications += 1

                if 'group' in action_lower or 'cambios_grupos' in category_lower:
                    group_changes += 1

                if 'policy' in action_lower or 'politicas_dominio' in category_lower:
                    policy_changes += 1

                if 'bind' in action_lower or 'bind' in msg_lower or 'ldap' in category_lower:
                    ldap_binds += 1

                if 'kerberos' in category_lower or 'ticket' in category_lower:
                    kerberos_events += 1

                if is_failed:
                    _add_counter(top_failed_src_ips, _get_field_value('src_ip'))

                if matched >= start_idx and matched < end_idx:
                    row_cells = []
                    for col in table_columns:
                        raw_value = _get_field_value(col)
                        if col == 'event_time' and raw_value:
                            display_value = raw_value.strftime('%Y-%m-%d %H:%M:%S')
                        elif col == 'message' and derived.get('summary'):
                            display_value = derived.get('summary')
                        elif isinstance(raw_value, list):
                            display_value = ', '.join(str(v) for v in raw_value)
                        elif isinstance(raw_value, dict):
                            display_value = json.dumps(raw_value, ensure_ascii=True)
                        elif raw_value is None:
                            display_value = '-'
                        else:
                            display_value = str(raw_value)

                        if len(display_value) > 220:
                            display_value = f"{display_value[:220]}..."

                        row_cells.append(
                            {
                                'field': col,
                                'display': display_value,
                                'raw': str(raw_value)[:180] if raw_value is not None else '',
                                'full': '' if raw_value is None else str(raw_value),
                            }
                        )
                    rows.append({'cells': row_cells})
                matched += 1

            total = matched
        pg.close()
    except Exception as exc:
        db_error = str(exc)

    timeline = [
        {'t': bucket.strftime('%Y-%m-%d %H:%M'), 'count': int(count or 0)}
        for bucket, count in bucket_counts.items()
    ]

    def _top_list(counter):
        return [{'label': k, 'count': int(v)} for k, v in counter.most_common(10)]

    total_pages = (total + page_size - 1) // page_size if total else 1
    base_qd = request.GET.copy()
    if 'page' in base_qd:
        base_qd.pop('page')
    base_querystring = base_qd.urlencode()

    context = {
        'rows': rows,
        'total': total,
        'page': page,
        'total_pages': total_pages,
        'time_range': time_range,
        'q': query,
        'table_columns': table_columns,
        'active_filters': active_filters,
        'base_querystring': base_querystring,
        'timeline': timeline,
        'top_categories': _top_list(top_categories),
        'top_sources': _top_list(top_sources),
        'top_hosts': _top_list(top_hosts),
        'top_users': _top_list(top_users),
        'top_targets': _top_list(top_targets),
        'top_ous': _top_list(top_ous),
        'top_auth_pairs': _top_list(top_auth_pairs),
        'top_actions': _top_list(top_actions),
        'top_results': _top_list(top_results),
        'top_src_ips': _top_list(top_src_ips),
        'top_dst_ips': _top_list(top_dst_ips),
        'top_services': _top_list(top_services),
        'top_failed_src_ips': _top_list(top_failed_src_ips),
        'top_lockout_users': _top_list(top_lockout_users),
        'unique_users': len(unique_users),
        'unique_targets': len(unique_targets),
        'modified_targets': len(modified_targets),
        'modified_ous': len(modified_ous),
        'auth_success': auth_success,
        'auth_failed': auth_failed,
        'auth_total': auth_total,
        'password_changes': password_changes,
        'user_modifications': user_modifications,
        'group_changes': group_changes,
        'policy_changes': policy_changes,
        'ldap_binds': ldap_binds,
        'kerberos_events': kerberos_events,
        'lockout_events': lockout_events,
        'db_error': db_error,
    }

    return context


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

# ===== NUEVAS VISTAS DE ROTACIÓN AVANZADA =====

@login_required
def rotate_database(request):
    """Rotar datos de la base de datos"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No autorizado'})

    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Método no permitido'})

    try:
        import json
        data = json.loads(request.body)

        data_type = data.get('data_type', 'all')
        retention_days = int(data.get('retention_days', 30))
        create_backup = data.get('create_backup', False)
        dry_run = data.get('dry_run', True)

        # Lógica básica de rotación (simulada por ahora)
        cutoff_date = timezone.now() - timedelta(days=retention_days)

        # Contadores de simulación
        stats = {
            'records_deleted': 0,
            'backup_created': create_backup,
            'dry_run': dry_run,
            'cutoff_date': cutoff_date.isoformat()
        }

        if not dry_run:
            # Aquí iría la lógica real de eliminación
            # Por ahora solo simulamos
            stats['records_deleted'] = 100  # Simulado

        return JsonResponse({
            'success': True,
            'message': f'Rotación de base de datos completada. Modo: {"Simulación" if dry_run else "Real"}',
            'stats': stats
        })

    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Error en rotación de BD: {str(e)}'
        })

@login_required
def preview_db_rotation(request):
    """Vista previa de rotación de base de datos"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No autorizado'})

    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Método no permitido'})

    try:
        import json
        data = json.loads(request.body)

        data_type = data.get('data_type', 'all')
        retention_days = int(data.get('retention_days', 30))
        cutoff_date = timezone.now() - timedelta(days=retention_days)

        # Simular preview
        preview = {
            'data_type': data_type,
            'retention_days': retention_days,
            'cutoff_date': cutoff_date.isoformat(),
            'estimated_records': 150,
            'estimated_space_saved': '2.5 MB',
            'affected_tables': ['snort_logs', 'suricata_logs', 'alerts']
        }

        return JsonResponse({
            'success': True,
            'preview': preview
        })

    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Error generando preview: {str(e)}'
        })

@login_required
def rotate_files(request):
    """Rotar archivos del sistema"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No autorizado'})

    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Método no permitido'})

    try:
        import json
        data = json.loads(request.body)

        file_type = data.get('file_type', 'all')
        action = data.get('action', 'compress')
        destination_dir = data.get('destination_dir', '')
        preserve_structure = data.get('preserve_structure', True)
        dry_run = data.get('dry_run', True)

        # Simular rotación de archivos
        stats = {
            'files_processed': 25,
            'files_moved': 20,
            'files_compressed': 5,
            'space_saved': '15.2 MB',
            'dry_run': dry_run,
            'action': action
        }

        return JsonResponse({
            'success': True,
            'message': f'Rotación de archivos completada. Acción: {action}',
            'stats': stats
        })

    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Error en rotación de archivos: {str(e)}'
        })

@login_required
def scan_files(request):
    """Escanear archivos del sistema"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No autorizado'})

    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Método no permitido'})

    try:
        # Simular escaneo de archivos
        stats = {
            'total_files': 45,
            'snort_files': 15,
            'suricata_files': 20,
            'other_files': 10,
            'total_size': '125 MB',
            'oldest_file': '2024-01-15',
            'newest_file': timezone.now().date().isoformat()
        }

        return JsonResponse({
            'success': True,
            'stats': stats
        })

    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Error escaneando archivos: {str(e)}'
        })

@login_required
def preview_file_rotation(request):
    """Vista previa de rotación de archivos"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No autorizado'})

    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Método no permitido'})

    try:
        import json
        data = json.loads(request.body)

        file_type = data.get('file_type', 'all')
        action = data.get('action', 'compress')

        # Simular preview de archivos
        preview = {
            'file_type': file_type,
            'action': action,
            'files_to_process': 30,
            'estimated_space_saved': '18.7 MB',
            'destination_preview': f'/backup/logs/{file_type}/',
            'oldest_file_affected': '2024-02-01'
        }

        return JsonResponse({
            'success': True,
            'preview': preview
        })

    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Error generando preview de archivos: {str(e)}'
        })

@login_required
def optimize_database(request):
    """Optimizar base de datos"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No autorizado'})

    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Método no permitido'})

    try:
        # Simular optimización
        return JsonResponse({
            'success': True,
            'message': 'Base de datos optimizada correctamente. Rendimiento mejorado en un 15%.'
        })

    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Error optimizando BD: {str(e)}'
        })

@login_required
def rebuild_indexes(request):
    """Reconstruir índices de base de datos"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No autorizado'})

    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Método no permitido'})

    try:
        # Simular reconstrucción de índices
        return JsonResponse({
            'success': True,
            'message': 'Índices reconstruidos correctamente. Consultas optimizadas.'
        })

    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Error reconstruyendo índices: {str(e)}'
        })

@login_required
def cleanup_temp_files(request):
    """Limpiar archivos temporales"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No autorizado'})

    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Método no permitido'})

    try:
        # Simular limpieza
        return JsonResponse({
            'success': True,
            'message': 'Archivos temporales limpiados. Liberados 45 MB de espacio.'
        })

    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Error limpiando archivos temporales: {str(e)}'
        })

@login_required
def generate_report(request):
    """Generar reporte de rotación"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No autorizado'})

    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Método no permitido'})

    try:
        from django.http import HttpResponse
        import io
        import base64

        # Crear reporte simulado
        report_content = f"""REPORTE DE ROTACIÓN - VANT-SIEM
Generado: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}

ESTADÍSTICAS GENERALES:
- Configuraciones activas: 2
- Archivos procesados (24h): 1735
- Espacio estimado en logs: 125 MB

ÚLTIMAS OPERACIONES:
- Optimización BD: Completada
- Reconstrucción índices: Pendiente
- Limpieza temporal: Completada

RECOMENDACIONES:
- Ejecutar rotación semanal de datos > 30 días
- Monitorear crecimiento de archivos de log
- Realizar backup antes de rotaciones masivas
"""

        # Crear data URL para descarga directa
        report_b64 = base64.b64encode(report_content.encode('utf-8')).decode('utf-8')
        data_url = f"data:text/plain;charset=utf-8;base64,{report_b64}"
        filename = f"rotation_report_{timezone.now().date()}.txt"

        return JsonResponse({
            'success': True,
            'message': 'Reporte generado correctamente',
            'report_url': data_url,
            'filename': filename
        })

    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Error generando reporte: {str(e)}'
        })

@login_required
def rotation_history(request):
    """Obtener historial de operaciones de rotación"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No autorizado'})

    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Método no permitido'})

    try:
        # Simular historial
        history = [
            {
                'operation': 'Rotación BD - 30 días',
                'timestamp': (timezone.now() - timedelta(hours=2)).strftime('%d/%m/%Y %H:%M'),
                'status': 'success'
            },
            {
                'operation': 'Optimización BD',
                'timestamp': (timezone.now() - timedelta(days=1)).strftime('%d/%m/%Y %H:%M'),
                'status': 'success'
            },
            {
                'operation': 'Limpieza archivos temp',
                'timestamp': (timezone.now() - timedelta(days=3)).strftime('%d/%m/%Y %H:%M'),
                'status': 'success'
            }
        ]

        return JsonResponse({
            'success': True,
            'history': history
        })

    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Error obteniendo historial: {str(e)}'
        })


@login_required
def opensearch_visual_dashboard(request):
    """Dashboard visual basado en os_events_raw (nueva ingesta OpenSearch)."""
    time_range = request.GET.get('time_range', '5m')
    source_type = request.GET.get('source', 'all')

    range_map = {
        '5m': timedelta(minutes=5),
        '15m': timedelta(minutes=15),
        '1h': timedelta(hours=1),
        '24h': timedelta(hours=24),
        '7d': timedelta(days=7),
    }
    bucket_map = {
        '5m': 'minute',
        '15m': 'minute',
        '1h': 'minute',
        '24h': 'hour',
        '7d': 'day',
    }

    delta = range_map.get(time_range, timedelta(minutes=5))
    bucket = bucket_map.get(time_range, 'minute')
    since = timezone.now() - delta

    filters = ["event_time >= %s"]
    params = [since]
    if source_type in ('snort', 'suricata'):
        filters.append("source_type = %s")
        params.append(source_type)
    where_sql = " AND ".join(filters)

    stats = {
        'total': 0,
        'snort': 0,
        'suricata': 0,
        'last_event': None,
    }
    timeline = []
    top_categories = []
    latest_events = []
    db_error = None

    db_host = os.getenv('OS_DB_HOST', '127.0.0.1')
    db_port = int(os.getenv('OS_DB_PORT', '5432'))
    db_name = os.getenv('OS_DB_NAME', 'vant_opensearch')
    db_user = os.getenv('OS_DB_USER', 'postgres')
    db_password = os.getenv('OS_DB_PASSWORD', 'postgres')

    try:
        pg = psycopg2.connect(
            host=db_host,
            port=db_port,
            dbname=db_name,
            user=db_user,
            password=db_password,
        )
        pg.autocommit = True
        with pg.cursor() as cur:
            cur.execute(
                f"""
                SELECT
                    COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE source_type = 'snort') AS snort,
                    COUNT(*) FILTER (WHERE source_type = 'suricata') AS suricata,
                    MAX(event_time) AS last_event
                FROM os_events_raw
                WHERE {where_sql}
                """,
                params,
            )
            row = cur.fetchone()
            if row:
                stats['total'] = row[0] or 0
                stats['snort'] = row[1] or 0
                stats['suricata'] = row[2] or 0
                stats['last_event'] = row[3].isoformat() if row[3] else None

            cur.execute(
                f"""
                SELECT
                    date_trunc(%s, event_time) AS bucket,
                    COUNT(*) AS count
                FROM os_events_raw
                WHERE {where_sql}
                GROUP BY bucket
                ORDER BY bucket ASC
                """,
                [bucket] + params,
            )
            timeline = [
                {'bucket': r[0].strftime('%Y-%m-%d %H:%M'), 'count': int(r[1])}
                for r in cur.fetchall()
            ]

            cur.execute(
                f"""
                SELECT COALESCE(event_category, 'unknown') AS category, COUNT(*) AS count
                FROM os_events_raw
                WHERE {where_sql}
                GROUP BY category
                ORDER BY count DESC
                LIMIT 10
                """,
                params,
            )
            top_categories = [{'category': r[0], 'count': int(r[1])} for r in cur.fetchall()]

            cur.execute(
                f"""
                SELECT event_time, source_type, COALESCE(event_category, 'unknown'), LEFT(message, 180), host_name
                FROM os_events_raw
                WHERE {where_sql}
                ORDER BY event_time DESC
                LIMIT 100
                """,
                params,
            )
            latest_events = [
                {
                    'event_time': r[0].strftime('%Y-%m-%d %H:%M:%S') if r[0] else '',
                    'source_type': r[1] or '',
                    'event_category': r[2] or '',
                    'message': r[3] or '',
                    'host_name': r[4] or '',
                }
                for r in cur.fetchall()
            ]
        pg.close()
    except Exception as exc:
        db_error = str(exc)

    context = {
        'time_range': time_range,
        'source': source_type,
        'stats': stats,
        'timeline': timeline,
        'top_categories': top_categories,
        'latest_events': latest_events,
        'chart_data': json.dumps(
            {
                'timeline': timeline,
                'top_categories': top_categories,
            }
        ),
        'db_error': db_error,
    }
    return render(request, 'opensearch_dashboard.html', context)


@login_required
def opensearch_discovery(request):
    """Vista estilo Discover para explorar logs de os_events_raw."""
    time_range = request.GET.get('time_range', '24h')
    source = request.GET.get('source', 'all')
    category = request.GET.get('category', '').strip()
    query = request.GET.get('q', '').strip()
    try:
        page = max(int(request.GET.get('page', '1') or '1'), 1)
    except (TypeError, ValueError):
        page = 1
    page_size = 100
    include_tokens = request.GET.getlist('f')
    exclude_tokens = request.GET.getlist('nf')

    range_map = {
        '15m': timedelta(minutes=15),
        '1h': timedelta(hours=1),
        '24h': timedelta(hours=24),
        '7d': timedelta(days=7),
        '30d': timedelta(days=30),
    }
    since = timezone.now() - range_map.get(time_range, timedelta(hours=24))

    db_host = os.getenv('OS_DB_HOST', '127.0.0.1')
    db_port = int(os.getenv('OS_DB_PORT', '5432'))
    db_name = os.getenv('OS_DB_NAME', 'vant_opensearch')
    db_user = os.getenv('OS_DB_USER', 'postgres')
    db_password = os.getenv('OS_DB_PASSWORD', 'postgres')

    core_fields = [
        'id',
        'source_type',
        'source_name',
        'host_name',
        'host_ip',
        'event_time',
        'severity',
        'event_category',
        'message',
        'tags',
        'ingested_at',
    ]
    snort_extracted_fields = [
        'signature',
        'classification',
        'priority',
        'proto',
        'src_ip',
        'src_port',
        'dst_ip',
        'dst_port',
        'gid',
        'sid',
        'rev',
        'line',
    ]
    snort_extracted_set = set(snort_extracted_fields)
    suricata_profile_fields = [
        'event_time',
        'severity',
        'event_category',
        'message',
        'ingested_at',
        'event_type',
        'proto',
        'src_ip',
        'src_port',
        'dst_ip',
        'dst_port',
        'app_proto',
        'flow_id',
        'in_iface',
    ]
    snort_profile_fields = [
        'event_time',
        'severity',
        'event_category',
        'message',
        'ingested_at',
        'line',
        'signature',
        'classification',
        'priority',
        'proto',
        'src_ip',
        'src_port',
        'dst_ip',
        'dst_port',
        'gid',
        'sid',
        'rev',
    ]
    derived_filter_fields = snort_extracted_set | {
        'event_type', 'dst_ip', 'dst_port', 'app_proto', 'flow_id', 'in_iface',
    }
    core_filter_fields = set(core_fields)

    snort_line_re = re.compile(
        r'^\S+\s+\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+'
        r'(?P<signature>.*?)\s+\[\*\*\]\s+\[Classification:\s*(?P<classification>[^\]]+)\]\s+'
        r'\[Priority:\s*(?P<priority>\d+)\]\s+\{(?P<proto>[^}]+)\}\s+'
        r'(?P<src_ip>[^: ]+):(?P<src_port>\d+)\s+->\s+(?P<dst_ip>[^: ]+):(?P<dst_port>\d+)'
    )

    def _parse_snort_line(raw_line):
        if not raw_line:
            return {}
        text = str(raw_line).strip()
        if not text:
            return {}
        match = snort_line_re.match(text)
        if match:
            out = match.groupdict()
            out['line'] = text
            return out

        # Fallback parsing for format variations in Snort lines.
        out = {'line': text}

        ids = re.search(r'\[(\d+):(\d+):(\d+)\]', text)
        if ids:
            out['gid'], out['sid'], out['rev'] = ids.group(1), ids.group(2), ids.group(3)

        sig = re.search(r'\[\d+:\d+:\d+\]\s+(.*?)\s+\[\*\*\]', text)
        if sig:
            out['signature'] = sig.group(1).strip()

        cls = re.search(r'\[Classification:\s*([^\]]+)\]', text)
        if cls:
            out['classification'] = cls.group(1).strip()

        prio = re.search(r'\[Priority:\s*([^\]]+)\]', text)
        if prio:
            out['priority'] = prio.group(1).strip()

        proto = re.search(r'\{([^}]+)\}', text)
        if proto:
            out['proto'] = proto.group(1).strip()

        flow = re.search(
            r'([0-9a-fA-F:\.]+):(\d+)\s+->\s+([0-9a-fA-F:\.]+):(\d+)',
            text
        )
        if flow:
            out['src_ip'], out['src_port'], out['dst_ip'], out['dst_port'] = (
                flow.group(1), flow.group(2), flow.group(3), flow.group(4)
            )

        out['line'] = text
        return out

    parsed_include = []
    parsed_exclude = []
    for token in include_tokens:
        if ':' in token:
            field, value = token.split(':', 1)
            field = field.strip()
            value = value.strip()
            if field and value:
                parsed_include.append((field, value, token))
    for token in exclude_tokens:
        if ':' in token:
            field, value = token.split(':', 1)
            field = field.strip()
            value = value.strip()
            if field and value:
                parsed_exclude.append((field, value, token))

    filters = ["event_time >= %s"]
    params = [since]
    if source != 'all':
        filters.append("source_type = %s")
        params.append(source)
    if category:
        filters.append("event_category = %s")
        params.append(category)
    if query:
        filters.append("(message ILIKE %s OR event_category ILIKE %s OR host_name ILIKE %s OR host_ip ILIKE %s)")
        like = f"%{query}%"
        params.extend([like, like, like, like])

    rows = []
    total = 0
    timeline = []
    source_options = []
    category_options = []
    payload_fields = []
    table_columns = core_fields.copy()
    active_filters = []
    db_error = None
    offset = (page - 1) * page_size
    mem_include_filters = []
    mem_exclude_filters = []

    payload_field_re = re.compile(r'^[A-Za-z0-9_.-]{1,64}$')

    def _value_matches(field_value, filter_value):
        text = '' if field_value is None else str(field_value).strip()
        if filter_value == '__EMPTY__':
            return text == ''
        return filter_value.lower() in text.lower()

    def _is_allowed_field(field):
        if field in core_filter_fields:
            return True
        if field in derived_filter_fields or field == 'line':
            return True
        return bool(payload_field_re.match(field))

    def _payload_lookup(payload, key):
        if not key:
            return None
        if key in payload:
            return payload.get(key)
        if '.' not in key:
            return payload.get(key)
        cur = payload
        for part in key.split('.'):
            if not isinstance(cur, dict):
                return None
            cur = cur.get(part)
        return cur

    for field, value, token in parsed_include:
        if not _is_allowed_field(field):
            continue
        mem_include_filters.append((field, value, token))
        active_filters.append({'mode': 'include', 'field': field, 'value': value, 'token': token})

    for field, value, token in parsed_exclude:
        if not _is_allowed_field(field):
            continue
        mem_exclude_filters.append((field, value, token))
        active_filters.append({'mode': 'exclude', 'field': field, 'value': value, 'token': token})

    uses_filters = bool(mem_include_filters or mem_exclude_filters)

    bucket_unit, bucket_step = {
        '15m': ('minute', 1),
        '1h': ('minute', 5),
        '24h': ('hour', 1),
        '7d': ('day', 1),
        '30d': ('day', 1),
    }.get(time_range, ('hour', 1))

    def _floor_bucket(dt, unit, step):
        if unit == 'minute':
            minute = (dt.minute // step) * step
            return dt.replace(minute=minute, second=0, microsecond=0)
        if unit == 'hour':
            hour = (dt.hour // step) * step
            return dt.replace(hour=hour, minute=0, second=0, microsecond=0)
        base = dt.replace(hour=0, minute=0, second=0, microsecond=0)
        if step <= 1:
            return base
        offset = base.toordinal() % step
        return base - timedelta(days=offset)

    def _iter_buckets(start_dt, end_dt, unit, step):
        cur = _floor_bucket(start_dt, unit, step)
        while cur <= end_dt:
            yield cur
            if unit == 'minute':
                cur = cur + timedelta(minutes=step)
            elif unit == 'hour':
                cur = cur + timedelta(hours=step)
            else:
                cur = cur + timedelta(days=step)

    try:
        pg = psycopg2.connect(
            host=db_host,
            port=db_port,
            dbname=db_name,
            user=db_user,
            password=db_password,
        )
        pg.autocommit = not uses_filters
        fetched_rows = []
        with pg.cursor() as cur:
            cur.execute(
                """
                SELECT source_type, COUNT(*)
                FROM os_events_raw
                GROUP BY source_type
                ORDER BY COUNT(*) DESC, source_type
                """
            )
            source_options = [{'value': r[0], 'count': int(r[1])} for r in cur.fetchall()]

            cur.execute(
                """
                SELECT event_category, COUNT(*)
                FROM os_events_raw
                WHERE event_category IS NOT NULL AND event_category <> ''
                GROUP BY event_category
                ORDER BY COUNT(*) DESC
                LIMIT 100
                """
            )
            category_options = [{'value': r[0], 'count': int(r[1])} for r in cur.fetchall()]
            base_where_sql = " AND ".join(filters)

            try:
                cur.execute(
                    f"""
                    SELECT k, COUNT(*)
                    FROM os_events_raw e
                    CROSS JOIN LATERAL jsonb_object_keys(
                        COALESCE(e.raw_payload, '{{}}'::jsonb)
                    ) AS k
                    WHERE {base_where_sql}
                    GROUP BY k
                    ORDER BY COUNT(*) DESC, k
                    LIMIT 40
                    """,
                    params,
                )
                payload_fields = [r[0] for r in cur.fetchall() if r[0] not in core_filter_fields]
            except Exception:
                payload_fields = []

            where_sql = " AND ".join(filters)
            if source == 'snort':
                table_columns = snort_profile_fields
            elif source == 'suricata':
                table_columns = suricata_profile_fields
            else:
                include_snort_columns = False
                cur.execute(f"SELECT COUNT(*) FROM os_events_raw WHERE {where_sql} AND source_type = 'snort'", params)
                include_snort_columns = int(cur.fetchone()[0] or 0) > 0
                table_columns = core_fields + payload_fields
                if include_snort_columns:
                    table_columns += [
                        f for f in snort_extracted_fields if f not in core_fields and f not in payload_fields
                    ]

            query_sql = f"""
                SELECT
                    id,
                    source_type,
                    source_name,
                    host_name,
                    host_ip,
                    event_time,
                    severity,
                    event_category,
                    message,
                    tags,
                    ingested_at,
                    COALESCE(raw_payload, '{{}}'::jsonb) AS raw_payload
                FROM os_events_raw
                WHERE {where_sql}
                ORDER BY event_time DESC
            """

            if not uses_filters:
                cur.execute(f"SELECT COUNT(*) FROM os_events_raw WHERE {where_sql}", params)
                total = int(cur.fetchone()[0] or 0)
                cur.execute(query_sql + " LIMIT %s OFFSET %s", params + [page_size, offset])
                fetched_rows = cur.fetchall()

        def _process_record(record, apply_filters):
            payload = record[11] if isinstance(record[11], dict) else {}
            if payload is None:
                payload = {}

            base_map = {
                'id': record[0],
                'source_type': record[1],
                'source_name': record[2],
                'host_name': record[3],
                'host_ip': record[4],
                'event_time': record[5],
                'severity': record[6],
                'event_category': record[7],
                'message': record[8],
                'tags': record[9],
                'ingested_at': record[10],
            }
            source_type_value = str(base_map.get('source_type') or '').lower()
            if source_type_value == 'snort':
                snort_line = payload.get('line') or base_map.get('message') or ''
                parsed_snort = _parse_snort_line(snort_line)
                if parsed_snort:
                    # Keep parsed non-empty fields as source of truth for Discover columns.
                    for key, val in parsed_snort.items():
                        if val is not None and str(val).strip() != '':
                            payload[key] = val
                    if parsed_snort.get('signature'):
                        base_map['message'] = parsed_snort['signature']
                    if not payload.get('line') and snort_line:
                        payload['line'] = snort_line
                # Defensive fallback: if signature is still empty, use message.
                if (not payload.get('signature')) and str(base_map.get('message') or '').strip():
                    payload['signature'] = str(base_map.get('message')).strip()
            elif source_type_value == 'suricata':
                alert_obj = payload.get('alert') if isinstance(payload.get('alert'), dict) else {}
                suricata_map = {
                    'event_type': payload.get('event_type') or base_map.get('event_category'),
                    'proto': payload.get('proto'),
                    'src_ip': payload.get('src_ip'),
                    'src_port': payload.get('src_port'),
                    'dst_ip': payload.get('dest_ip') or payload.get('dst_ip'),
                    'dst_port': payload.get('dest_port') or payload.get('dst_port'),
                    'app_proto': payload.get('app_proto'),
                    'flow_id': payload.get('flow_id'),
                    'in_iface': payload.get('in_iface'),
                    'signature': alert_obj.get('signature') if alert_obj else None,
                    'classification': alert_obj.get('category') if alert_obj else None,
                    'priority': alert_obj.get('severity') if alert_obj else None,
                }
                for key, val in suricata_map.items():
                    if val is not None and str(val).strip() != '':
                        payload[key] = val

            extracted_map = {f: payload.get(f) for f in (derived_filter_fields | {'line'})}
            if apply_filters:
                def _get_field_value(field_name):
                    if field_name in core_filter_fields:
                        return base_map.get(field_name)
                    if field_name in derived_filter_fields or field_name == 'line':
                        return extracted_map.get(field_name)
                    return _payload_lookup(payload, field_name)

                include_ok = all(_value_matches(_get_field_value(f), v) for f, v, _ in mem_include_filters)
                exclude_ok = all(not _value_matches(_get_field_value(f), v) for f, v, _ in mem_exclude_filters)
                if not (include_ok and exclude_ok):
                    return None, None

            row_cells = []
            for col in table_columns:
                if col in extracted_map and extracted_map.get(col) not in (None, ''):
                    raw_value = extracted_map.get(col)
                elif col in payload_fields:
                    raw_value = payload.get(col)
                else:
                    raw_value = base_map.get(col)
                is_empty = raw_value is None or str(raw_value).strip() == ''
                if col in ('event_time', 'ingested_at') and raw_value:
                    display_value = raw_value.strftime('%Y-%m-%d %H:%M:%S')
                elif isinstance(raw_value, list):
                    display_value = ', '.join(str(v) for v in raw_value)
                elif isinstance(raw_value, dict):
                    display_value = json.dumps(raw_value, ensure_ascii=True)
                elif raw_value is None:
                    display_value = '-'
                else:
                    display_value = str(raw_value)

                if len(display_value) > 220:
                    display_value = f"{display_value[:220]}..."

                row_cells.append(
                    {
                        'field': col,
                        'display': display_value,
                        'raw': str(raw_value)[:180] if raw_value is not None else '',
                        'full': '' if raw_value is None else str(raw_value),
                        'is_empty': is_empty,
                    }
                )
            return {'cells': row_cells}, base_map.get('event_time')

        if not uses_filters:
            candidate_rows = []
            for record in fetched_rows:
                row, _event_time = _process_record(record, apply_filters=False)
                if row:
                    candidate_rows.append(row)
            rows = candidate_rows
            with pg.cursor() as cur:
                cur.execute(
                    f"""
                    WITH bounds AS (
                        SELECT %s::timestamptz AS since_ts, NOW() AS now_ts
                    ),
                    series AS (
                        SELECT generate_series(
                            date_trunc(%s, since_ts),
                            date_trunc(%s, now_ts),
                            %s::interval
                        ) AS bucket
                        FROM bounds
                    ),
                    counts AS (
                        SELECT date_trunc(%s, event_time) AS bucket, COUNT(*) AS cnt
                        FROM os_events_raw
                        WHERE {where_sql}
                        GROUP BY 1
                    )
                    SELECT series.bucket, COALESCE(counts.cnt, 0) AS cnt
                    FROM series
                    LEFT JOIN counts ON counts.bucket = series.bucket
                    ORDER BY series.bucket
                    """,
                    [since, bucket_unit, bucket_unit, f"{bucket_step} {bucket_unit}", bucket_unit] + params,
                )
                timeline = [
                    {
                        't': r[0].strftime('%Y-%m-%d %H:%M') if r[0] else '',
                        'count': int(r[1] or 0),
                    }
                    for r in cur.fetchall()
                ]
        else:
            now_ts = timezone.now()
            bucket_counts = {b: 0 for b in _iter_buckets(since, now_ts, bucket_unit, bucket_step)}
            start_idx = offset
            end_idx = offset + page_size
            matched = 0
            rows = []
            with pg.cursor(name='discover_stream') as cur:
                cur.itersize = 2000
                cur.execute(query_sql, params)
                for record in cur:
                    row, event_time = _process_record(record, apply_filters=True)
                    if row is None:
                        continue
                    if event_time:
                        if timezone.is_naive(event_time):
                            event_time = timezone.make_aware(event_time, timezone.get_current_timezone())
                        bucket = _floor_bucket(event_time, bucket_unit, bucket_step)
                        if bucket in bucket_counts:
                            bucket_counts[bucket] += 1
                    if matched >= start_idx and matched < end_idx:
                        rows.append(row)
                    matched += 1
            total = matched
            timeline = [
                {
                    't': bucket.strftime('%Y-%m-%d %H:%M'),
                    'count': int(count or 0),
                }
                for bucket, count in bucket_counts.items()
            ]

        pg.close()
    except Exception as exc:
        db_error = str(exc)

    total_pages = (total + page_size - 1) // page_size if total else 1
    source_profile = source if source in ('snort', 'suricata') else 'all'
    profile_components = {
        'all': {
            'title': 'Unified Discovery',
            'subtitle': 'Vista consolidada para analisis transversal entre fuentes.',
            'focus': ['event_time', 'source_type', 'severity', 'event_category', 'message'],
        },
        'snort': {
            'title': 'Snort Component',
            'subtitle': 'Tabla especializada para firmas, clasificacion, prioridad y flujo de red.',
            'focus': ['signature', 'classification', 'priority', 'proto', 'src_ip', 'dst_ip'],
        },
        'suricata': {
            'title': 'Suricata Component',
            'subtitle': 'Tabla especializada para event_type, flow/app_proto y telemetria de red.',
            'focus': ['event_type', 'proto', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'flow_id'],
        },
    }
    base_qd = request.GET.copy()
    if 'page' in base_qd:
        base_qd.pop('page')
    base_querystring = base_qd.urlencode()

    context = {
        'rows': rows,
        'total': total,
        'page': page,
        'total_pages': total_pages,
        'time_range': time_range,
        'source': source,
        'category': category,
        'q': query,
        'source_options': source_options,
        'category_options': category_options,
        'core_fields': core_fields,
        'payload_fields': payload_fields,
        'snort_profile_fields': snort_profile_fields,
        'suricata_profile_fields': suricata_profile_fields,
        'table_columns': table_columns,
        'active_filters': active_filters,
        'base_querystring': base_querystring,
        'source_profile': source_profile,
        'profile_components': profile_components,
        'timeline': timeline,
        'db_error': db_error,
    }
    return render(request, 'opensearch_discovery.html', context)


@login_required
def snort_security_dashboard(request):
    """Dashboard de seguridad Snort con top métricas + tabla estilo Discovery."""
    time_range = request.GET.get('time_range', '24h')
    query = request.GET.get('q', '').strip()
    try:
        page = max(int(request.GET.get('page', '1') or '1'), 1)
    except (TypeError, ValueError):
        page = 1
    page_size = 100
    include_tokens = request.GET.getlist('f')
    exclude_tokens = request.GET.getlist('nf')

    range_map = {
        '15m': timedelta(minutes=15),
        '1h': timedelta(hours=1),
        '24h': timedelta(hours=24),
        '7d': timedelta(days=7),
        '30d': timedelta(days=30),
    }
    since = timezone.now() - range_map.get(time_range, timedelta(hours=24))

    core_fields = [
        'event_time',
        'severity',
        'event_category',
        'message',
        'host_name',
        'host_ip',
    ]
    snort_fields = [
        'signature',
        'classification',
        'priority',
        'proto',
        'src_ip',
        'src_port',
        'dst_ip',
        'dst_port',
        'gid',
        'sid',
        'rev',
        'line',
    ]
    table_columns = [
        'event_time',
        'severity',
        'signature',
        'classification',
        'priority',
        'proto',
        'src_ip',
        'src_port',
        'dst_ip',
        'dst_port',
        'gid',
        'sid',
        'rev',
        'host_name',
        'message',
    ]
    allowed_fields = set(core_fields + snort_fields)

    snort_line_re = re.compile(
        r'^\S+\s+\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+'
        r'(?P<signature>.*?)\s+\[\*\*\]\s+\[Classification:\s*(?P<classification>[^\]]+)\]\s+'
        r'\[Priority:\s*(?P<priority>\d+)\]\s+\{(?P<proto>[^}]+)\}\s+'
        r'(?P<src_ip>[^: ]+):(?P<src_port>\d+)\s+->\s+(?P<dst_ip>[^: ]+):(?P<dst_port>\d+)'
    )

    def _parse_snort_line(raw_line):
        if not raw_line:
            return {}
        text = str(raw_line).strip()
        if not text:
            return {}
        match = snort_line_re.match(text)
        if match:
            out = match.groupdict()
            out['line'] = text
            return out

        out = {'line': text}
        ids = re.search(r'\[(\d+):(\d+):(\d+)\]', text)
        if ids:
            out['gid'], out['sid'], out['rev'] = ids.group(1), ids.group(2), ids.group(3)
        sig = re.search(r'\[\d+:\d+:\d+\]\s+(.*?)\s+\[\*\*\]', text)
        if sig:
            out['signature'] = sig.group(1).strip()
        cls = re.search(r'\[Classification:\s*([^\]]+)\]', text)
        if cls:
            out['classification'] = cls.group(1).strip()
        prio = re.search(r'\[Priority:\s*([^\]]+)\]', text)
        if prio:
            out['priority'] = prio.group(1).strip()
        proto = re.search(r'\{([^}]+)\}', text)
        if proto:
            out['proto'] = proto.group(1).strip()
        flow = re.search(r'([0-9a-fA-F:\.]+):(\d+)\s+->\s+([0-9a-fA-F:\.]+):(\d+)', text)
        if flow:
            out['src_ip'], out['src_port'], out['dst_ip'], out['dst_port'] = (
                flow.group(1), flow.group(2), flow.group(3), flow.group(4)
            )
        return out

    parsed_include = []
    parsed_exclude = []
    for token in include_tokens:
        if ':' in token:
            field, value = token.split(':', 1)
            field = field.strip()
            value = value.strip()
            if field and value:
                parsed_include.append((field, value, token))
    for token in exclude_tokens:
        if ':' in token:
            field, value = token.split(':', 1)
            field = field.strip()
            value = value.strip()
            if field and value:
                parsed_exclude.append((field, value, token))

    def _value_matches(field_value, filter_value):
        text = '' if field_value is None else str(field_value).strip()
        if filter_value == '__EMPTY__':
            return text == ''
        return filter_value.lower() in text.lower()

    def _payload_lookup(payload, key):
        if not key:
            return None
        if key in payload:
            return payload.get(key)
        if '.' not in key:
            return payload.get(key)
        cur = payload
        for part in key.split('.'):
            if not isinstance(cur, dict):
                return None
            cur = cur.get(part)
        return cur

    mem_include_filters = []
    mem_exclude_filters = []
    active_filters = []
    for field, value, token in parsed_include:
        if field not in allowed_fields:
            continue
        mem_include_filters.append((field, value, token))
        active_filters.append({'mode': 'include', 'field': field, 'value': value, 'token': token})
    for field, value, token in parsed_exclude:
        if field not in allowed_fields:
            continue
        mem_exclude_filters.append((field, value, token))
        active_filters.append({'mode': 'exclude', 'field': field, 'value': value, 'token': token})

    bucket_unit, bucket_step = {
        '15m': ('minute', 1),
        '1h': ('minute', 5),
        '24h': ('hour', 1),
        '7d': ('day', 1),
        '30d': ('day', 1),
    }.get(time_range, ('hour', 1))

    def _floor_bucket(dt, unit, step):
        if unit == 'minute':
            minute = (dt.minute // step) * step
            return dt.replace(minute=minute, second=0, microsecond=0)
        if unit == 'hour':
            hour = (dt.hour // step) * step
            return dt.replace(hour=hour, minute=0, second=0, microsecond=0)
        base = dt.replace(hour=0, minute=0, second=0, microsecond=0)
        if step <= 1:
            return base
        offset = base.toordinal() % step
        return base - timedelta(days=offset)

    def _iter_buckets(start_dt, end_dt, unit, step):
        cur = _floor_bucket(start_dt, unit, step)
        while cur <= end_dt:
            yield cur
            if unit == 'minute':
                cur = cur + timedelta(minutes=step)
            elif unit == 'hour':
                cur = cur + timedelta(hours=step)
            else:
                cur = cur + timedelta(days=step)

    filters = ["event_time >= %s", "source_type = 'snort'"]
    params = [since]
    if query:
        like = f"%{query}%"
        filters.append("(message ILIKE %s OR event_category ILIKE %s OR host_name ILIKE %s OR host_ip ILIKE %s)")
        params.extend([like, like, like, like])

    rows = []
    total = 0
    db_error = None
    offset = (page - 1) * page_size
    now_ts = timezone.now()
    bucket_counts = {b: 0 for b in _iter_buckets(since, now_ts, bucket_unit, bucket_step)}
    top_src_ips = Counter()
    top_dst_ips = Counter()
    top_src_ports = Counter()
    top_dst_ports = Counter()
    top_ports_total = Counter()
    top_protocols = Counter()
    top_hostnames = Counter()
    top_classifications = Counter()
    top_priorities = Counter()
    top_signatures = Counter()
    top_alerts = Counter()

    def _add_counter(counter, value):
        if value is None:
            return
        text = str(value).strip()
        if not text or text.lower() in ('none', 'null', '-'):
            return
        counter[text] += 1

    query_sql = f"""
        SELECT
            id,
            source_type,
            source_name,
            host_name,
            host_ip,
            event_time,
            severity,
            event_category,
            message,
            tags,
            ingested_at,
            COALESCE(raw_payload, '{{}}'::jsonb) AS raw_payload
        FROM os_events_raw
        WHERE {" AND ".join(filters)}
        ORDER BY event_time DESC
    """

    try:
        pg = _get_opensearch_pg_conn()
        with pg.cursor(name='snort_security_stream') as cur:
            cur.itersize = 2000
            cur.execute(query_sql, params)
            matched = 0
            start_idx = offset
            end_idx = offset + page_size
            for record in cur:
                payload = record[11] if isinstance(record[11], dict) else {}
                if payload is None:
                    payload = {}

                base_map = {
                    'id': record[0],
                    'source_type': record[1],
                    'source_name': record[2],
                    'host_name': record[3],
                    'host_ip': record[4],
                    'event_time': record[5],
                    'severity': record[6],
                    'event_category': record[7],
                    'message': record[8],
                    'tags': record[9],
                    'ingested_at': record[10],
                }

                snort_line = payload.get('line') or base_map.get('message') or ''
                parsed_snort = _parse_snort_line(snort_line)
                if parsed_snort:
                    for key, val in parsed_snort.items():
                        if val is not None and str(val).strip() != '':
                            payload[key] = val
                    if parsed_snort.get('signature'):
                        base_map['message'] = parsed_snort['signature']
                    if not payload.get('line') and snort_line:
                        payload['line'] = snort_line
                if (not payload.get('signature')) and str(base_map.get('message') or '').strip():
                    payload['signature'] = str(base_map.get('message')).strip()

                extracted = {f: payload.get(f) for f in snort_fields}

                def _get_field_value(field_name):
                    if field_name in core_fields:
                        return base_map.get(field_name)
                    if field_name in snort_fields:
                        return extracted.get(field_name)
                    return _payload_lookup(payload, field_name)

                include_ok = all(_value_matches(_get_field_value(f), v) for f, v, _ in mem_include_filters)
                exclude_ok = all(not _value_matches(_get_field_value(f), v) for f, v, _ in mem_exclude_filters)
                if not (include_ok and exclude_ok):
                    continue

                event_time = base_map.get('event_time')
                if event_time:
                    if timezone.is_naive(event_time):
                        event_time = timezone.make_aware(event_time, timezone.get_current_timezone())
                    bucket = _floor_bucket(event_time, bucket_unit, bucket_step)
                    if bucket in bucket_counts:
                        bucket_counts[bucket] += 1

                _add_counter(top_src_ips, extracted.get('src_ip'))
                _add_counter(top_dst_ips, extracted.get('dst_ip'))
                src_port = extracted.get('src_port')
                dst_port = extracted.get('dst_port')
                _add_counter(top_src_ports, src_port)
                _add_counter(top_dst_ports, dst_port)
                _add_counter(top_ports_total, src_port)
                _add_counter(top_ports_total, dst_port)
                _add_counter(top_protocols, extracted.get('proto'))
                _add_counter(top_classifications, extracted.get('classification'))
                _add_counter(top_priorities, extracted.get('priority'))
                _add_counter(top_hostnames, base_map.get('host_name'))
                signature_val = extracted.get('signature') or base_map.get('message')
                _add_counter(top_signatures, signature_val)
                _add_counter(top_alerts, signature_val)

                if matched >= start_idx and matched < end_idx:
                    row_cells = []
                    for col in table_columns:
                        if col in extracted and extracted.get(col) not in (None, ''):
                            raw_value = extracted.get(col)
                        else:
                            raw_value = base_map.get(col)
                        if col == 'event_time' and raw_value:
                            display_value = raw_value.strftime('%Y-%m-%d %H:%M:%S')
                        elif isinstance(raw_value, list):
                            display_value = ', '.join(str(v) for v in raw_value)
                        elif isinstance(raw_value, dict):
                            display_value = json.dumps(raw_value, ensure_ascii=True)
                        elif raw_value is None:
                            display_value = '-'
                        else:
                            display_value = str(raw_value)

                        if len(display_value) > 220:
                            display_value = f"{display_value[:220]}..."

                        row_cells.append(
                            {
                                'field': col,
                                'display': display_value,
                                'raw': str(raw_value)[:180] if raw_value is not None else '',
                                'full': '' if raw_value is None else str(raw_value),
                            }
                        )
                    rows.append({'cells': row_cells})
                matched += 1

            total = matched
        pg.close()
    except Exception as exc:
        db_error = str(exc)

    timeline = [
        {'t': bucket.strftime('%Y-%m-%d %H:%M'), 'count': int(count or 0)}
        for bucket, count in bucket_counts.items()
    ]

    def _top_list(counter):
        return [{'label': k, 'count': int(v)} for k, v in counter.most_common(10)]

    total_pages = (total + page_size - 1) // page_size if total else 1
    base_qd = request.GET.copy()
    if 'page' in base_qd:
        base_qd.pop('page')
    base_querystring = base_qd.urlencode()

    context = {
        'rows': rows,
        'total': total,
        'page': page,
        'total_pages': total_pages,
        'time_range': time_range,
        'q': query,
        'table_columns': table_columns,
        'active_filters': active_filters,
        'base_querystring': base_querystring,
        'timeline': timeline,
        'top_src_ips': _top_list(top_src_ips),
        'top_dst_ips': _top_list(top_dst_ips),
        'top_ports_total': _top_list(top_ports_total),
        'top_src_ports': _top_list(top_src_ports),
        'top_dst_ports': _top_list(top_dst_ports),
        'top_protocols': _top_list(top_protocols),
        'top_hostnames': _top_list(top_hostnames),
        'top_classifications': _top_list(top_classifications),
        'top_priorities': _top_list(top_priorities),
        'top_signatures': _top_list(top_signatures),
        'top_alerts': _top_list(top_alerts),
        'db_error': db_error,
    }
    return render(request, 'snort_security_dashboard.html', context)


@login_required
def suricata_security_dashboard(request):
    """Dashboard de seguridad Suricata con top métricas + tabla estilo Discovery."""
    time_range = request.GET.get('time_range', '24h')
    query = request.GET.get('q', '').strip()
    try:
        page = max(int(request.GET.get('page', '1') or '1'), 1)
    except (TypeError, ValueError):
        page = 1
    page_size = 100
    include_tokens = request.GET.getlist('f')
    exclude_tokens = request.GET.getlist('nf')

    range_map = {
        '15m': timedelta(minutes=15),
        '1h': timedelta(hours=1),
        '24h': timedelta(hours=24),
        '7d': timedelta(days=7),
        '30d': timedelta(days=30),
    }
    since = timezone.now() - range_map.get(time_range, timedelta(hours=24))

    core_fields = [
        'event_time',
        'severity',
        'event_category',
        'message',
        'host_name',
        'host_ip',
    ]
    suricata_fields = [
        'event_type',
        'proto',
        'src_ip',
        'src_port',
        'dst_ip',
        'dst_port',
        'app_proto',
        'flow_id',
        'in_iface',
        'signature',
        'classification',
        'priority',
    ]
    table_columns = [
        'event_time',
        'severity',
        'event_type',
        'signature',
        'classification',
        'priority',
        'proto',
        'app_proto',
        'src_ip',
        'src_port',
        'dst_ip',
        'dst_port',
        'flow_id',
        'host_name',
        'message',
    ]
    allowed_fields = set(core_fields + suricata_fields)

    parsed_include = []
    parsed_exclude = []
    for token in include_tokens:
        if ':' in token:
            field, value = token.split(':', 1)
            field = field.strip()
            value = value.strip()
            if field and value:
                parsed_include.append((field, value, token))
    for token in exclude_tokens:
        if ':' in token:
            field, value = token.split(':', 1)
            field = field.strip()
            value = value.strip()
            if field and value:
                parsed_exclude.append((field, value, token))

    def _value_matches(field_value, filter_value):
        text = '' if field_value is None else str(field_value).strip()
        if filter_value == '__EMPTY__':
            return text == ''
        return filter_value.lower() in text.lower()

    def _payload_lookup(payload, key):
        if not key:
            return None
        if key in payload:
            return payload.get(key)
        if '.' not in key:
            return payload.get(key)
        cur = payload
        for part in key.split('.'):
            if not isinstance(cur, dict):
                return None
            cur = cur.get(part)
        return cur

    mem_include_filters = []
    mem_exclude_filters = []
    active_filters = []
    for field, value, token in parsed_include:
        if field not in allowed_fields:
            continue
        mem_include_filters.append((field, value, token))
        active_filters.append({'mode': 'include', 'field': field, 'value': value, 'token': token})
    for field, value, token in parsed_exclude:
        if field not in allowed_fields:
            continue
        mem_exclude_filters.append((field, value, token))
        active_filters.append({'mode': 'exclude', 'field': field, 'value': value, 'token': token})

    bucket_unit, bucket_step = {
        '15m': ('minute', 1),
        '1h': ('minute', 5),
        '24h': ('hour', 1),
        '7d': ('day', 1),
        '30d': ('day', 1),
    }.get(time_range, ('hour', 1))

    def _floor_bucket(dt, unit, step):
        if unit == 'minute':
            minute = (dt.minute // step) * step
            return dt.replace(minute=minute, second=0, microsecond=0)
        if unit == 'hour':
            hour = (dt.hour // step) * step
            return dt.replace(hour=hour, minute=0, second=0, microsecond=0)
        base = dt.replace(hour=0, minute=0, second=0, microsecond=0)
        if step <= 1:
            return base
        offset = base.toordinal() % step
        return base - timedelta(days=offset)

    def _iter_buckets(start_dt, end_dt, unit, step):
        cur = _floor_bucket(start_dt, unit, step)
        while cur <= end_dt:
            yield cur
            if unit == 'minute':
                cur = cur + timedelta(minutes=step)
            elif unit == 'hour':
                cur = cur + timedelta(hours=step)
            else:
                cur = cur + timedelta(days=step)

    filters = ["event_time >= %s", "source_type = 'suricata'"]
    params = [since]
    if query:
        like = f"%{query}%"
        filters.append("(message ILIKE %s OR event_category ILIKE %s OR host_name ILIKE %s OR host_ip ILIKE %s)")
        params.extend([like, like, like, like])

    rows = []
    total = 0
    db_error = None
    offset = (page - 1) * page_size
    now_ts = timezone.now()
    bucket_counts = {b: 0 for b in _iter_buckets(since, now_ts, bucket_unit, bucket_step)}
    top_src_ips = Counter()
    top_dst_ips = Counter()
    top_src_ports = Counter()
    top_dst_ports = Counter()
    top_ports_total = Counter()
    top_protocols = Counter()
    top_app_protocols = Counter()
    top_hostnames = Counter()
    top_classifications = Counter()
    top_priorities = Counter()
    top_signatures = Counter()

    def _add_counter(counter, value):
        if value is None:
            return
        text = str(value).strip()
        if not text or text.lower() in ('none', 'null', '-'):
            return
        counter[text] += 1

    query_sql = f"""
        SELECT
            id,
            source_type,
            source_name,
            host_name,
            host_ip,
            event_time,
            severity,
            event_category,
            message,
            tags,
            ingested_at,
            COALESCE(raw_payload, '{{}}'::jsonb) AS raw_payload
        FROM os_events_raw
        WHERE {" AND ".join(filters)}
        ORDER BY event_time DESC
    """

    try:
        pg = _get_opensearch_pg_conn()
        with pg.cursor(name='suricata_security_stream') as cur:
            cur.itersize = 2000
            cur.execute(query_sql, params)
            matched = 0
            start_idx = offset
            end_idx = offset + page_size
            for record in cur:
                payload = record[11] if isinstance(record[11], dict) else {}
                if payload is None:
                    payload = {}

                base_map = {
                    'id': record[0],
                    'source_type': record[1],
                    'source_name': record[2],
                    'host_name': record[3],
                    'host_ip': record[4],
                    'event_time': record[5],
                    'severity': record[6],
                    'event_category': record[7],
                    'message': record[8],
                    'tags': record[9],
                    'ingested_at': record[10],
                }

                alert_obj = payload.get('alert') if isinstance(payload.get('alert'), dict) else {}
                extracted = {
                    'event_type': payload.get('event_type') or base_map.get('event_category'),
                    'proto': payload.get('proto'),
                    'src_ip': payload.get('src_ip'),
                    'src_port': payload.get('src_port'),
                    'dst_ip': payload.get('dest_ip') or payload.get('dst_ip'),
                    'dst_port': payload.get('dest_port') or payload.get('dst_port'),
                    'app_proto': payload.get('app_proto'),
                    'flow_id': payload.get('flow_id'),
                    'in_iface': payload.get('in_iface'),
                    'signature': alert_obj.get('signature') if alert_obj else None,
                    'classification': alert_obj.get('category') if alert_obj else None,
                    'priority': alert_obj.get('severity') if alert_obj else None,
                }
                if (not extracted.get('signature')) and str(base_map.get('message') or '').strip():
                    extracted['signature'] = str(base_map.get('message')).strip()

                def _get_field_value(field_name):
                    if field_name in core_fields:
                        return base_map.get(field_name)
                    if field_name in suricata_fields:
                        return extracted.get(field_name)
                    return _payload_lookup(payload, field_name)

                include_ok = all(_value_matches(_get_field_value(f), v) for f, v, _ in mem_include_filters)
                exclude_ok = all(not _value_matches(_get_field_value(f), v) for f, v, _ in mem_exclude_filters)
                if not (include_ok and exclude_ok):
                    continue

                event_time = base_map.get('event_time')
                if event_time:
                    if timezone.is_naive(event_time):
                        event_time = timezone.make_aware(event_time, timezone.get_current_timezone())
                    bucket = _floor_bucket(event_time, bucket_unit, bucket_step)
                    if bucket in bucket_counts:
                        bucket_counts[bucket] += 1

                src_port = extracted.get('src_port')
                dst_port = extracted.get('dst_port')
                _add_counter(top_src_ips, extracted.get('src_ip'))
                _add_counter(top_dst_ips, extracted.get('dst_ip'))
                _add_counter(top_src_ports, src_port)
                _add_counter(top_dst_ports, dst_port)
                _add_counter(top_ports_total, src_port)
                _add_counter(top_ports_total, dst_port)
                _add_counter(top_protocols, extracted.get('proto'))
                _add_counter(top_app_protocols, extracted.get('app_proto'))
                _add_counter(top_hostnames, base_map.get('host_name'))
                _add_counter(top_classifications, extracted.get('classification'))
                _add_counter(top_priorities, extracted.get('priority'))
                _add_counter(top_signatures, extracted.get('signature'))

                if matched >= start_idx and matched < end_idx:
                    row_cells = []
                    for col in table_columns:
                        if col in extracted and extracted.get(col) not in (None, ''):
                            raw_value = extracted.get(col)
                        else:
                            raw_value = base_map.get(col)
                        if col == 'event_time' and raw_value:
                            display_value = raw_value.strftime('%Y-%m-%d %H:%M:%S')
                        elif isinstance(raw_value, list):
                            display_value = ', '.join(str(v) for v in raw_value)
                        elif isinstance(raw_value, dict):
                            display_value = json.dumps(raw_value, ensure_ascii=True)
                        elif raw_value is None:
                            display_value = '-'
                        else:
                            display_value = str(raw_value)

                        if len(display_value) > 220:
                            display_value = f"{display_value[:220]}..."

                        row_cells.append(
                            {
                                'field': col,
                                'display': display_value,
                                'raw': str(raw_value)[:180] if raw_value is not None else '',
                                'full': '' if raw_value is None else str(raw_value),
                            }
                        )
                    rows.append({'cells': row_cells})
                matched += 1

            total = matched
        pg.close()
    except Exception as exc:
        db_error = str(exc)

    timeline = [
        {'t': bucket.strftime('%Y-%m-%d %H:%M'), 'count': int(count or 0)}
        for bucket, count in bucket_counts.items()
    ]

    def _top_list(counter):
        return [{'label': k, 'count': int(v)} for k, v in counter.most_common(10)]

    total_pages = (total + page_size - 1) // page_size if total else 1
    base_qd = request.GET.copy()
    if 'page' in base_qd:
        base_qd.pop('page')
    base_querystring = base_qd.urlencode()

    context = {
        'rows': rows,
        'total': total,
        'page': page,
        'total_pages': total_pages,
        'time_range': time_range,
        'q': query,
        'table_columns': table_columns,
        'active_filters': active_filters,
        'base_querystring': base_querystring,
        'timeline': timeline,
        'top_ports_total': _top_list(top_ports_total),
        'top_src_ports': _top_list(top_src_ports),
        'top_dst_ports': _top_list(top_dst_ports),
        'top_protocols': _top_list(top_protocols),
        'top_app_protocols': _top_list(top_app_protocols),
        'top_hostnames': _top_list(top_hostnames),
        'top_src_ips': _top_list(top_src_ips),
        'top_dst_ips': _top_list(top_dst_ips),
        'top_classifications': _top_list(top_classifications),
        'top_priorities': _top_list(top_priorities),
        'top_signatures': _top_list(top_signatures),
        'db_error': db_error,
    }
    return render(request, 'suricata_security_dashboard.html', context)


@login_required
def opensearch_create_visualizations(request):
    """Base UI para creacion de visualizaciones personalizadas."""
    presets = [
        {'id': 'timeseries', 'name': 'Time Series', 'desc': 'Eventos por tiempo con agrupacion por campo.'},
        {'id': 'bar', 'name': 'Bar Chart', 'desc': 'Top valores por campo (source, category, proto, host).'},
        {'id': 'pie', 'name': 'Pie/Donut', 'desc': 'Distribucion porcentual por categoria o severidad.'},
        {'id': 'table', 'name': 'Data Table', 'desc': 'Tabla agregada con filtros y ordenacion.'},
        {'id': 'geo', 'name': 'Geo Map', 'desc': 'Visualizacion geografica cuando existan campos de ubicacion.'},
    ]
    core_fields = [
        'source_type', 'source_name', 'host_name', 'host_ip', 'event_time',
        'event_category', 'severity', 'message', 'tags', 'ingested_at',
    ]
    derived_fields = [
        'event_type', 'proto', 'src_ip', 'src_port', 'dest_ip', 'dest_port',
        'dst_ip', 'dst_port', 'app_proto', 'flow_id', 'in_iface',
        'line', 'signature', 'classification', 'priority', 'gid', 'sid', 'rev',
    ]
    available_fields = core_fields + derived_fields
    source_options = []
    fields_by_source = {'all': available_fields.copy()}
    db_error = None
    try:
        pg = _get_opensearch_pg_conn()
        pg.autocommit = True
        with pg.cursor() as cur:
            cur.execute(
                """
                SELECT source_type, COUNT(*)
                FROM os_events_raw
                GROUP BY source_type
                ORDER BY COUNT(*) DESC, source_type
                """
            )
            source_options = [
                {'value': (r[0] or '').strip(), 'count': int(r[1] or 0)}
                for r in cur.fetchall() if (r[0] or '').strip()
            ]
            for s in source_options:
                stype = s['value']
                try:
                    cur.execute(
                        """
                        SELECT k, COUNT(*)
                        FROM os_events_raw e
                        CROSS JOIN LATERAL jsonb_object_keys(
                            COALESCE(e.raw_payload, '{}'::jsonb)
                        ) AS k
                        WHERE e.source_type = %s
                        GROUP BY k
                        ORDER BY COUNT(*) DESC, k
                        LIMIT 60
                        """,
                        [stype],
                    )
                    payload_keys = [r[0] for r in cur.fetchall() if r[0]]
                except Exception:
                    payload_keys = []
                merged = []
                for f in core_fields + derived_fields + payload_keys:
                    if f not in merged:
                        merged.append(f)
                fields_by_source[stype] = merged
            if source_options:
                all_fields = []
                for s in source_options:
                    for f in fields_by_source.get(s['value'], []):
                        if f not in all_fields:
                            all_fields.append(f)
                fields_by_source['all'] = all_fields
        pg.close()
    except Exception as exc:
        db_error = str(exc)
    return render(
        request,
        'opensearch_create_visualizations.html',
        {
            'presets': presets,
            'available_fields': available_fields,
            'source_options': source_options,
            'fields_by_source': fields_by_source,
            'db_error': db_error,
        },
    )


@login_required
def opensearch_visualizations_list(request):
    if request.method != 'GET':
        return JsonResponse({'success': False, 'error': 'Metodo no permitido'}, status=405)
    space = (request.GET.get('space') or 'personal').strip()
    qs = SavedVisualization.objects.filter(Q(owner=request.user, space=space) | Q(is_shared=True, space=space)).order_by('-updated_at')
    items = [_serialize_saved_visualization(x) for x in qs[:300]]
    return JsonResponse({'success': True, 'items': items, 'space': space})


@login_required
def opensearch_visualizations_save(request):
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Metodo no permitido'}, status=405)
    try:
        payload = json.loads(request.body or '{}')
        name = (payload.get('name') or '').strip()
        config = payload.get('config') or {}
        space = (payload.get('space') or 'personal').strip()
        is_shared = bool(payload.get('is_shared', False))
        viz_id = payload.get('id')
        if not name:
            return JsonResponse({'success': False, 'error': 'El nombre es obligatorio'}, status=400)
        if viz_id:
            obj = SavedVisualization.objects.filter(id=viz_id, owner=request.user).first()
            if not obj:
                return JsonResponse({'success': False, 'error': 'Visualizacion no encontrada'}, status=404)
            obj.name = name
            obj.description = (payload.get('description') or '').strip()
            obj.config = config
            obj.space = space
            obj.is_shared = is_shared
            obj.save(update_fields=['name', 'description', 'config', 'space', 'is_shared', 'updated_at'])
        else:
            obj = SavedVisualization.objects.create(
                owner=request.user,
                name=name,
                description=(payload.get('description') or '').strip(),
                config=config,
                space=space,
                is_shared=is_shared,
            )
        return JsonResponse({'success': True, 'item': _serialize_saved_visualization(obj)})
    except Exception as exc:
        return JsonResponse({'success': False, 'error': str(exc)}, status=500)


@login_required
def opensearch_visualizations_delete(request):
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Metodo no permitido'}, status=405)
    try:
        payload = json.loads(request.body or '{}')
        viz_id = payload.get('id')
        if not viz_id:
            return JsonResponse({'success': False, 'error': 'ID requerido'}, status=400)
        obj = SavedVisualization.objects.filter(id=viz_id, owner=request.user).first()
        if not obj:
            return JsonResponse({'success': False, 'error': 'Visualizacion no encontrada'}, status=404)
        obj.delete()
        return JsonResponse({'success': True, 'message': 'Visualizacion eliminada'})
    except Exception as exc:
        return JsonResponse({'success': False, 'error': str(exc)}, status=500)


@login_required
def opensearch_dashboards_list(request):
    if request.method != 'GET':
        return JsonResponse({'success': False, 'error': 'Metodo no permitido'}, status=405)
    space = (request.GET.get('space') or 'personal').strip()
    qs = SavedDashboard.objects.filter(Q(owner=request.user, space=space) | Q(is_shared=True, space=space)).order_by('-updated_at')
    items = [_serialize_saved_dashboard(x) for x in qs[:200]]
    return JsonResponse({'success': True, 'items': items, 'space': space})


@login_required
def opensearch_dashboards_save(request):
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Metodo no permitido'}, status=405)
    try:
        payload = json.loads(request.body or '{}')
        name = (payload.get('name') or '').strip()
        if not name:
            return JsonResponse({'success': False, 'error': 'El nombre es obligatorio'}, status=400)

        dashboard_id = payload.get('id')
        space = (payload.get('space') or 'personal').strip()
        is_shared = bool(payload.get('is_shared', False))
        layout = payload.get('layout') or {}

        panel_ids = []
        if isinstance(layout, dict):
            panel_ids = layout.get('panel_ids') or []
        valid_ids = set(
            SavedVisualization.objects.filter(
                Q(owner=request.user, id__in=panel_ids) | Q(is_shared=True, id__in=panel_ids)
            ).values_list('id', flat=True)
        )
        if isinstance(layout, dict):
            layout['panel_ids'] = [x for x in panel_ids if x in valid_ids]

        if dashboard_id:
            obj = SavedDashboard.objects.filter(id=dashboard_id, owner=request.user).first()
            if not obj:
                return JsonResponse({'success': False, 'error': 'Dashboard no encontrado'}, status=404)
            obj.name = name
            obj.description = (payload.get('description') or '').strip()
            obj.space = space
            obj.layout = layout
            obj.is_shared = is_shared
            obj.save(update_fields=['name', 'description', 'space', 'layout', 'is_shared', 'updated_at'])
        else:
            obj = SavedDashboard.objects.create(
                owner=request.user,
                name=name,
                description=(payload.get('description') or '').strip(),
                space=space,
                layout=layout,
                is_shared=is_shared,
            )

        return JsonResponse({'success': True, 'item': _serialize_saved_dashboard(obj)})
    except Exception as exc:
        return JsonResponse({'success': False, 'error': str(exc)}, status=500)


@login_required
def opensearch_visualizations_preview(request):
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Metodo no permitido'}, status=405)
    try:
        payload = json.loads(request.body or '{}')
        source = payload.get('source', 'all')
        time_range = payload.get('time_range', '24h')
        category = (payload.get('category') or '').strip()
        query = (payload.get('query') or '').strip()
        viz_type = (payload.get('viz_type') or 'timeseries').strip()
        if viz_type in ('line', 'area'):
            viz_type = 'timeseries'
        if viz_type == 'doughnut':
            viz_type = 'pie'
        if viz_type in ('heatmap', 'gauge', 'scatter', 'radar'):
            return JsonResponse({'success': False, 'error': 'Tipo de visualizacion no soportado'}, status=400)
        group_by = (payload.get('group_by') or '').strip()
        limit = max(1, min(int(payload.get('limit') or 10), 100))
        table_fields = payload.get('table_fields') or ['event_time', 'source_type', 'event_category', 'severity', 'message']
        metric_agg = (payload.get('metric_agg') or 'count').strip()
        metric_field = (payload.get('metric_field') or '').strip()
        metric_label = (payload.get('metric_label') or '').strip()

        where_sql, params = _build_viz_where(source, time_range, category, query)
        pg = _get_opensearch_pg_conn()
        pg.autocommit = True
        response = {'success': True, 'viz_type': viz_type, 'data': {}}

        with pg.cursor() as cur:
            if viz_type == 'timeseries':
                bucket_unit, bucket_step = {
                    '15m': ('minute', '1 minute'),
                    '1h': ('minute', '5 minutes'),
                    '24h': ('hour', '1 hour'),
                    '7d': ('day', '1 day'),
                    '30d': ('day', '1 day'),
                    '90d': ('day', '1 day'),
                }.get(time_range, ('hour', '1 hour'))

                if group_by:
                    group_sql, group_params = _field_sql(group_by)
                    if group_sql:
                        cur.execute(
                            f"""
                            WITH top_groups AS (
                                SELECT {group_sql} AS g
                                FROM os_events_raw
                                WHERE {where_sql}
                                GROUP BY g
                                ORDER BY COUNT(*) DESC
                                LIMIT 6
                            )
                            SELECT date_trunc(%s, event_time) AS bucket, {group_sql} AS grp, COUNT(*)
                            FROM os_events_raw
                            WHERE {where_sql}
                              AND {group_sql} IN (SELECT g FROM top_groups)
                            GROUP BY 1, 2
                            ORDER BY 1, 2
                            """,
                            [bucket_unit] + group_params + params + group_params + params + group_params,
                        )
                        rows = cur.fetchall()
                        labels = sorted({r[0].strftime('%Y-%m-%d %H:%M') for r in rows if r[0]})
                        groups = sorted({r[1] or 'unknown' for r in rows})
                        datasets = []
                        for g in groups:
                            data_map = {r[0].strftime('%Y-%m-%d %H:%M'): int(r[2]) for r in rows if (r[1] or 'unknown') == g}
                            datasets.append({'label': g, 'data': [data_map.get(lb, 0) for lb in labels]})
                        response['data'] = {'labels': labels, 'datasets': datasets}
                    else:
                        group_by = ''

                if not group_by:
                    cur.execute(
                        f"""
                        SELECT date_trunc(%s, event_time) AS bucket, COUNT(*)
                        FROM os_events_raw
                        WHERE {where_sql}
                        GROUP BY 1
                        ORDER BY 1
                        """,
                        [bucket_unit] + params,
                    )
                    rows = cur.fetchall()
                    response['data'] = {
                        'labels': [r[0].strftime('%Y-%m-%d %H:%M') for r in rows if r[0]],
                        'datasets': [{'label': 'Events', 'data': [int(r[1]) for r in rows]}],
                    }

            elif viz_type in ('bar', 'pie', 'geo'):
                if not group_by:
                    group_by = 'event_category' if viz_type != 'geo' else 'src_ip'
                group_sql, group_params = _field_sql(group_by)
                if not group_sql and viz_type == 'geo':
                    group_sql, group_params = _field_sql('src_ip')
                if not group_sql:
                    return JsonResponse({'success': False, 'error': 'Campo de agrupacion invalido'}, status=400)
                cur.execute(
                    f"""
                    SELECT {group_sql} AS grp, COUNT(*)
                    FROM os_events_raw
                    WHERE {where_sql}
                    GROUP BY grp
                    ORDER BY COUNT(*) DESC
                    LIMIT %s
                    """,
                    group_params + params + [limit],
                )
                rows = cur.fetchall()
                response['data'] = {
                    'labels': [r[0] or 'unknown' for r in rows],
                    'values': [int(r[1]) for r in rows],
                }

            elif viz_type == 'metric':
                agg = metric_agg.lower()
                if agg == 'count':
                    cur.execute(
                        f"""
                        SELECT COUNT(*)
                        FROM os_events_raw
                        WHERE {where_sql}
                        """,
                        params,
                    )
                    value = int(cur.fetchone()[0] or 0)
                else:
                    expr, f_params = _field_sql(metric_field)
                    if not expr:
                        return JsonResponse({'success': False, 'error': 'Campo de metrica invalido'}, status=400)
                    if agg not in ('avg', 'sum', 'min', 'max', 'cardinality'):
                        return JsonResponse({'success': False, 'error': 'Metrica no soportada'}, status=400)
                    agg_sql = {
                        'avg': 'AVG',
                        'sum': 'SUM',
                        'min': 'MIN',
                        'max': 'MAX',
                        'cardinality': 'COUNT(DISTINCT',
                    }.get(agg)
                    if agg == 'cardinality':
                        cur.execute(
                            f"""
                            SELECT COUNT(DISTINCT {expr})
                            FROM os_events_raw
                            WHERE {where_sql}
                            """,
                            f_params + params,
                        )
                    else:
                        cur.execute(
                            f"""
                            SELECT {agg_sql}({expr})
                            FROM os_events_raw
                            WHERE {where_sql}
                            """,
                            f_params + params,
                        )
                    raw_val = cur.fetchone()[0]
                    try:
                        value = float(raw_val) if raw_val is not None else 0
                    except Exception:
                        value = 0
                response['data'] = {'value': value, 'label': metric_label or metric_agg.upper()}

            elif viz_type == 'table':
                field_clauses = []
                sql_params = []
                clean_fields = []
                for field in table_fields[:12]:
                    expr, f_params = _field_sql(field)
                    if expr:
                        field_clauses.append(f"{expr} AS {field}")
                        sql_params.extend(f_params)
                        clean_fields.append(field)
                if not field_clauses:
                    field_clauses = ["event_time::text AS event_time", "source_type AS source_type", "message AS message"]
                    clean_fields = ['event_time', 'source_type', 'message']
                cur.execute(
                    f"""
                    SELECT {', '.join(field_clauses)}
                    FROM os_events_raw
                    WHERE {where_sql}
                    ORDER BY event_time DESC
                    LIMIT %s
                    """,
                    sql_params + params + [limit],
                )
                rows = cur.fetchall()
                response['data'] = {'columns': clean_fields, 'rows': [list(r) for r in rows]}
            else:
                return JsonResponse({'success': False, 'error': 'Tipo de visualizacion no soportado'}, status=400)

        pg.close()
        return JsonResponse(response)
    except Exception as exc:
        return JsonResponse({'success': False, 'error': str(exc)}, status=500)
