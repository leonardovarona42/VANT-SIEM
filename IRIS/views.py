import logging
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.db.models import Count, Q
from django.urls import reverse_lazy, reverse
from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView
from django.http import JsonResponse
from datetime import timedelta
import json

from .models import (
    AIModelConfig, AIPerformanceMetrics, HumanFeedback,
    AIAnalysisLog, AIConfiguration, IncidentPrediction
)
from EVENT_M.models import Incidente
from .ai_incident_investigator import AIIncidentInvestigator

logger = logging.getLogger(__name__)

class AIDashboardView(ListView):
    """Dashboard principal del sistema de IA"""
    template_name = 'IRIS/dashboard.html'
    context_object_name = 'ai_incidents'
    paginate_by = 10

    def get_queryset(self):
        # Incidentes creados por IA recientemente
        return Incidente.objects.filter(
            reporte__nombre_informante='Sistema de IA Automático',
            fecha_hora__gte=timezone.now() - timedelta(days=7)
        ).order_by('-fecha_hora')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Manejar acciones desde el navbar
        action = self.request.GET.get('action')

        if action == 'run_analysis':
            # Ejecutar análisis desde el navbar
            investigator = AIIncidentInvestigator()
            predictions_created, incidents_created = investigator.analyze_recent_logs(hours_back=24)

            messages.success(
                self.request,
                f'Análisis SOAR completado desde navbar. {predictions_created} predicciones, {incidents_created} incidentes creados.'
            )

            # Log del análisis
            AIAnalysisLog.objects.create(
                analysis_type='pattern_analysis',
                start_time=timezone.now() - timedelta(hours=24),
                end_time=timezone.now(),
                incidents_created=incidents_created,
                success=True
            )

        elif action == 'train_models':
            # Entrenar modelos desde el navbar
            investigator = AIIncidentInvestigator()
            investigator.train_models()

            messages.success(self.request, 'Modelos de IA entrenados exitosamente desde navbar.')

            # Log del entrenamiento
            AIAnalysisLog.objects.create(
                analysis_type='anomaly_detection',
                start_time=timezone.now(),
                end_time=timezone.now(),
                success=True
            )

        # Obtener métricas recientes
        today = timezone.now().date()
        week_ago = today - timedelta(days=7)

        # Métricas de rendimiento
        context['performance_metrics'] = AIPerformanceMetrics.objects.filter(
            date__gte=week_ago
        ).order_by('-date')

        # Predicciones pendientes de validación
        context['pending_predictions'] = IncidentPrediction.objects.filter(
            status='pending'
        ).order_by('-created_at')[:5]

        # Logs de análisis recientes
        context['recent_analysis'] = AIAnalysisLog.objects.all().order_by('-created_at')[:10]

        # Configuración actual
        config = AIConfiguration.objects.first()
        if not config:
            config = AIConfiguration.objects.create()
        context['config'] = config

        # Modelos activos
        context['active_models'] = AIModelConfig.objects.filter(is_active=True)

        # Total de incidentes hoy
        context['total_incidents_today'] = context['object_list'].count()

        return context

    def render_to_response(self, context, **response_kwargs):
        # Check if this is an AJAX request
        if self.request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            # Return JSON data for AJAX requests
            incidents_data = []
            for incident in context['object_list']:
                incidents_data.append({
                    'id': incident.id,
                    'nombre_incidente': incident.nombre_incidente,
                    'descripcion': incident.descripcion[:100],
                    'estado_solucion': incident.get_estado_solucion_display(),
                    'fecha_hora': incident.fecha_hora.strftime('%d/%m/%Y %H:%M'),
                    'detail_url': reverse('eventos:incidente-detail', args=[incident.id]),
                })

            data = {
                'incidents': incidents_data,
                'has_next': context['page_obj'].has_next(),
                'has_previous': context['page_obj'].has_previous(),
                'current_page': context['page_obj'].number,
                'total_pages': context['page_obj'].paginator.num_pages,
                'total_count': context['paginator'].count
            }
            return JsonResponse(data)
        else:
            # Return normal HTML response
            return super().render_to_response(context, **response_kwargs)

class AIAnalysisCreateView(CreateView):
    """Vista para ejecutar análisis de IA manualmente"""
    model = AIAnalysisLog
    template_name = 'IRIS/analysis_form.html'
    fields = ['analysis_type']
    success_url = reverse_lazy('iris:iris_dashboard')

    def form_valid(self, form):
        # Ejecutar el análisis
        hours_back = int(self.request.POST.get('hours_back', 24))

        try:
            investigator = AIIncidentInvestigator()
            incidents_created = investigator.analyze_recent_logs(hours_back)

            # Actualizar el objeto con resultados
            form.instance.start_time = timezone.now() - timedelta(hours=hours_back)
            form.instance.end_time = timezone.now()
            form.instance.incidents_created = incidents_created
            form.instance.success = True

            messages.success(
                self.request,
                f'Análisis completado. Se crearon {incidents_created} incidentes.'
            )

        except Exception as e:
            form.instance.start_time = timezone.now() - timedelta(hours=hours_back)
            form.instance.end_time = timezone.now()
            form.instance.success = False
            form.instance.error_message = str(e)

            messages.error(self.request, f'Error en análisis: {str(e)}')

        return super().form_valid(form)

@login_required
def human_feedback(request, incident_id):
    """Vista para proporcionar feedback humano sobre incidentes de IA"""
    incident = get_object_or_404(Incidente, id=incident_id)

    if request.method == 'POST':
        feedback_type = request.POST.get('feedback_type')
        correct_classification = request.POST.get('correct_classification', '')
        confidence_level = int(request.POST.get('confidence_level', 5))
        comments = request.POST.get('comments', '')

        # Crear feedback
        HumanFeedback.objects.create(
            incident=incident,
            user=request.user,
            feedback_type=feedback_type,
            correct_classification=correct_classification if correct_classification else None,
            confidence_level=confidence_level,
            comments=comments
        )

        # Actualizar predicción si existe
        prediction = IncidentPrediction.objects.filter(created_incident=incident).first()
        if prediction:
            if feedback_type == 'false_positive':
                prediction.status = 'rejected'
            elif feedback_type == 'good_prediction':
                prediction.status = 'validated'
            prediction.validated_at = timezone.now()
            prediction.validated_by = request.user
            prediction.save()

        # Incorporar feedback al modelo de IA
        investigator = AIIncidentInvestigator()
        investigator.incorporate_human_feedback(
            incident_id,
            feedback_type == 'false_positive',
            correct_classification if correct_classification else None
        )

        messages.success(request, 'Feedback registrado exitosamente. El modelo se actualizará automáticamente.')

        return redirect('eventos:incidente-detail', pk=incident_id)

    context = {
        'incident': incident,
        'feedback_types': HumanFeedback.FEEDBACK_TYPES,
    }

    return render(request, 'IRIS/human_feedback.html', context)

class IncidentPredictionListView(ListView):
    """Lista de predicciones de incidentes pendientes de validación"""
    model = IncidentPrediction
    template_name = 'IRIS/predictions_list.html'
    context_object_name = 'predictions'
    paginate_by = 10

    def get_queryset(self):
        queryset = super().get_queryset()
        q = self.request.GET.get('q')
        if q:
            queryset = queryset.filter(
                Q(incident_type__icontains=q) |
                Q(description__icontains=q) |
                Q(status__icontains=q)
            )
        return queryset.filter(status='pending').order_by('-created_at')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['search_query'] = self.request.GET.get('q', '')
        return context

@login_required
def validate_prediction(request, prediction_id):
    """Validar o rechazar una predicción de IA"""
    prediction = get_object_or_404(IncidentPrediction, id=prediction_id)

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'validate':
            # Crear incidente real basado en la predicción
            from EVENT_M.models import Reporte, Area

            area = Area.objects.filter(nombre__icontains='seguridad').first()
            if not area:
                area = Area.objects.first()

            reporte = Reporte.objects.create(
                nombre_informante='Sistema de IA Automático (Validado)',
                email_informante='ai@vantsiem.com',
                descripcion=prediction.description,
                estado_solucion='Atendido',
                area=area,
                fecha_hora=prediction.created_at
            )

            incidente = Incidente.objects.create(
                nombre_incidente=f'{prediction.incident_type} - Validado por humano',
                descripcion=prediction.description,
                estado_solucion='investigacion',
                reporte=reporte,
                fecha_hora=prediction.created_at
            )

            prediction.created_incident = incidente
            prediction.status = 'validated'
            messages.success(request, 'Predicción validada e incidente creado.')

        elif action == 'reject':
            prediction.status = 'rejected'
            messages.info(request, 'Predicción rechazada.')

        prediction.validated_at = timezone.now()
        prediction.validated_by = request.user
        prediction.save()

        return redirect('iris:iris_predictions')

    context = {
        'prediction': prediction,
    }

    return render(request, 'IRIS/validate_prediction.html', context)

class AIConfigurationUpdateView(UpdateView):
    """Configuración del sistema de IA"""
    model = AIConfiguration
    template_name = 'IRIS/configuration.html'
    fields = [
        'auto_analysis_enabled', 'analysis_interval_hours', 'anomaly_threshold',
        'min_confidence_score', 'max_incidents_per_hour', 'require_human_approval',
        'learning_enabled', 'feedback_retrain_threshold'
    ]
    success_url = reverse_lazy('iris:iris_configuration')

    def get_object(self, queryset=None):
        # Siempre devolver la primera configuración o crear una nueva
        config = AIConfiguration.objects.first()
        if not config:
            config = AIConfiguration.objects.create()
        return config

    def form_valid(self, form):
        # Procesar valores booleanos correctamente
        boolean_fields = ['auto_analysis_enabled', 'require_human_approval', 'learning_enabled']
        for field_name in boolean_fields:
            if field_name in self.request.POST:
                form.instance.__setattr__(field_name, True)
            else:
                form.instance.__setattr__(field_name, False)

        response = super().form_valid(form)
        messages.success(self.request, 'Configuración actualizada exitosamente.')
        return response

@login_required
def performance_report(request):
    """Reporte de rendimiento del sistema de IA"""
    # Obtener métricas de los últimos 30 días
    end_date = timezone.now().date()
    start_date = end_date - timedelta(days=30)

    metrics = AIPerformanceMetrics.objects.filter(
        date__gte=start_date,
        date__lte=end_date
    ).order_by('date')

    # Preparar datos para gráficos
    dates = [m.date.strftime('%Y-%m-%d') for m in metrics]
    accuracy_data = [m.accuracy * 100 for m in metrics]
    precision_data = [m.precision * 100 for m in metrics]
    incidents_created_data = [m.incidents_created for m in metrics]

    # Estadísticas generales
    total_predictions = sum(m.total_predictions for m in metrics)
    total_tp = sum(m.true_positives for m in metrics)
    total_fp = sum(m.false_positives for m in metrics)
    total_incidents = sum(m.incidents_created for m in metrics)

    overall_accuracy = (total_tp / total_predictions * 100) if total_predictions > 0 else 0
    overall_precision = (total_tp / (total_tp + total_fp) * 100) if (total_tp + total_fp) > 0 else 0

    context = {
        'metrics': metrics,
        'dates': json.dumps(dates),
        'accuracy_data': json.dumps(accuracy_data),
        'precision_data': json.dumps(precision_data),
        'incidents_created_data': json.dumps(incidents_created_data),
        'overall_accuracy': overall_accuracy,
        'overall_precision': overall_precision,
        'total_incidents': total_incidents,
        'total_predictions': total_predictions,
    }

    return render(request, 'IRIS/performance_report.html', context)

@login_required
def train_models(request):
    """Entrenar modelos de IA manualmente"""
    if request.method == 'POST':
        try:
            investigator = AIIncidentInvestigator()
            investigator.train_models()

            messages.success(request, 'Modelos de IA entrenados exitosamente.')

            # Log del entrenamiento
            AIAnalysisLog.objects.create(
                analysis_type='anomaly_detection',
                start_time=timezone.now(),
                end_time=timezone.now(),
                success=True
            )

        except Exception as e:
            messages.error(request, f'Error entrenando modelos: {str(e)}')
            AIAnalysisLog.objects.create(
                analysis_type='anomaly_detection',
                start_time=timezone.now(),
                end_time=timezone.now(),
                success=False,
                error_message=str(e)
            )

    return redirect('iris:iris_dashboard')

@login_required
def live_ai_monitor(request):
    """Vista de monitoreo en vivo de la actividad de IA"""
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        # Return JSON data for AJAX requests
        recent_logs = AIAnalysisLog.objects.all().order_by('-created_at')[:10]
        recent_predictions = IncidentPrediction.objects.filter(
            created_at__gte=timezone.now() - timedelta(hours=1)
        ).order_by('-created_at')[:5]

        stats = {
            'total_predictions_today': IncidentPrediction.objects.filter(
                created_at__date=timezone.now().date()
            ).count(),
            'active_analysis': AIAnalysisLog.objects.filter(
                created_at__gte=timezone.now() - timedelta(minutes=30)
            ).count(),
            'recent_incidents': Incidente.objects.filter(
                fecha_hora__gte=timezone.now() - timedelta(hours=24),
                reporte__nombre_informante='Sistema de IA Automático'
            ).count()
        }

        logs_data = []
        for log in recent_logs:
            logs_data.append({
                'type': log.get_analysis_type_display(),
                'start_time': log.start_time.strftime('%H:%M:%S'),
                'duration': f"{log.processing_time:.2f}s",
                'incidents_created': log.incidents_created,
                'success': log.success,
                'error_message': log.error_message if not log.success else None
            })

        predictions_data = []
        for pred in recent_predictions:
            predictions_data.append({
                'incident_type': pred.incident_type,
                'confidence_score': float(pred.confidence_score),
                'description': pred.description[:100],
                'created_at': pred.created_at.strftime('%H:%M:%S'),
                'status': pred.get_status_display()
            })

        return JsonResponse({
            'stats': stats,
            'logs': logs_data,
            'predictions': predictions_data
        })

    # Obtener datos para la vista inicial
    recent_logs = AIAnalysisLog.objects.all().order_by('-created_at')[:10]
    recent_predictions = IncidentPrediction.objects.filter(
        created_at__gte=timezone.now() - timedelta(hours=1)
    ).order_by('-created_at')[:5]

    # Estadísticas en tiempo real
    stats = {
        'total_predictions_today': IncidentPrediction.objects.filter(
            created_at__date=timezone.now().date()
        ).count(),
        'active_analysis': AIAnalysisLog.objects.filter(
            created_at__gte=timezone.now() - timedelta(minutes=30)
        ).count(),
        'recent_incidents': Incidente.objects.filter(
            fecha_hora__gte=timezone.now() - timedelta(hours=24),
            reporte__nombre_informante='Sistema de IA Automático'
        ).count()
    }

    context = {
        'recent_logs': recent_logs,
        'recent_predictions': recent_predictions,
        'stats': stats,
    }

    return render(request, 'IRIS/live.html', context)
