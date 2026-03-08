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
    AIAnalysisLog, AIConfiguration, IncidentPrediction,
    AIRateLimit, AICircuitBreaker, AIAuditLog, AIAlert
)
from EVENT_M.models import Incidente
from .ai_incident_investigator import AIIncidentInvestigator
from django import forms

logger = logging.getLogger(__name__)

class AIConfigurationForm(forms.ModelForm):
    """Formulario personalizado para configuración de IA"""

    alert_email_recipients = forms.CharField(
        required=False,
        initial='[]',
        widget=forms.Textarea(attrs={'rows': 3, 'placeholder': '["admin@example.com", "security@example.com"]'}),
        help_text='Lista de direcciones de email en formato JSON para recibir alertas del sistema.'
    )

    class Meta:
        model = AIConfiguration
        fields = [
            # Adoption Phase
            'adoption_phase',

            # Core Settings
            'auto_analysis_enabled', 'analysis_interval_hours', 'anomaly_threshold',
            'min_confidence_score',

            # Rate Limiting and Safety
            'max_incidents_per_hour', 'max_predictions_per_hour', 'circuit_breaker_threshold',
            'circuit_breaker_enabled',

            # Approval and Automation
            'require_human_approval', 'auto_create_incidents', 'auto_apply_measures',

            # Learning and Adaptation
            'learning_enabled', 'feedback_retrain_threshold', 'adaptive_thresholds',

            # Alerting and Monitoring
            'enable_performance_alerts', 'enable_anomaly_alerts', 'alert_email_recipients',

            # Advanced Features
            'enable_deep_learning', 'enable_external_integrations', 'correlation_time_window'
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Asegurar valores iniciales para campos requeridos
        if self.instance and self.instance.pk:
            # Para campos que podrían estar vacíos, establecer valores por defecto
            if not self.instance.max_incidents_per_hour:
                self.instance.max_incidents_per_hour = 10
            if not self.instance.max_predictions_per_hour:
                self.instance.max_predictions_per_hour = 50
            if not self.instance.feedback_retrain_threshold:
                self.instance.feedback_retrain_threshold = 10

            # Convertir lista de emails a JSON string para el formulario
            if hasattr(self.instance, 'alert_email_recipients') and isinstance(self.instance.alert_email_recipients, list):
                self.initial['alert_email_recipients'] = json.dumps(self.instance.alert_email_recipients)

    def clean_alert_email_recipients(self):
        """Validar y convertir el campo de emails"""
        email_data = self.cleaned_data.get('alert_email_recipients', '').strip()
        if email_data:
            try:
                email_list = json.loads(email_data)
                if not isinstance(email_list, list):
                    raise forms.ValidationError('Debe ser una lista de emails en formato JSON.')
                return email_list
            except json.JSONDecodeError:
                raise forms.ValidationError('Formato JSON inválido para emails.')
        return []

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

        # Controles de seguridad
        context['rate_limits'] = AIRateLimit.objects.all()
        context['circuit_breaker'] = AICircuitBreaker.objects.filter(name='ai_incident_investigator').first()

        # Alertas activas
        context['active_alerts'] = AIAlert.objects.filter(
            is_active=True,
            resolved=False
        ).order_by('-created_at')[:10]

        # Logs de auditoría recientes
        context['recent_audit_logs'] = AIAuditLog.objects.all().order_by('-created_at')[:20]

        # Estadísticas de alertas por tipo
        context['alerts_by_type'] = AIAlert.objects.filter(
            created_at__gte=timezone.now() - timedelta(days=7)
        ).values('alert_type').annotate(
            count=Count('id')
        ).order_by('-count')

        # Opciones de tipos de alerta para el template
        context['alert_type_choices'] = AIAlert._meta.get_field('alert_type').choices

        # Estado del sistema
        context['system_status'] = self.get_system_status()

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

    def get_system_status(self):
            """Obtener estado general del sistema IRIS"""
            status = {
                'overall_health': 'healthy',
                'warnings': [],
                'critical_issues': []
            }
    
            # Verificar circuit breaker
            cb = AICircuitBreaker.objects.filter(name='ai_incident_investigator').first()
            if cb and cb.state == 'open':
                status['overall_health'] = 'critical'
                status['critical_issues'].append('Circuit Breaker Abierto - Sistema bloqueado')
    
            # Verificar límites de tasa
            blocked_limits = AIRateLimit.objects.filter(is_blocked=True)
            if blocked_limits.exists():
                status['overall_health'] = 'warning'
                status['warnings'].append(f'{blocked_limits.count()} límites de tasa excedidos')
    
            # Verificar alertas críticas
            critical_alerts = AIAlert.objects.filter(
                priority='critical',
                is_active=True,
                resolved=False
            )
            if critical_alerts.exists():
                status['overall_health'] = 'critical'
                status['critical_issues'].append(f'{critical_alerts.count()} alertas críticas activas')
    
            # Verificar modelos activos
            active_models = AIModelConfig.objects.filter(is_active=True).count()
            if active_models == 0:
                status['overall_health'] = 'warning'
                status['warnings'].append('No hay modelos de IA activos')
    
            # Verificar configuración
            config = AIConfiguration.objects.first()
            if config and config.adoption_phase == 'passive':
                status['warnings'].append('Sistema en modo pasivo - sin automatización')
    
            return status

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
    form_class = AIConfigurationForm
    template_name = 'IRIS/configuration.html'
    success_url = reverse_lazy('iris:iris_configuration')

    def dispatch(self, request, *args, **kwargs):
        print(f"DEBUG: AIConfigurationUpdateView dispatch called - method: {request.method}")
        if request.method == 'POST':
            print(f"DEBUG: POST data keys: {list(request.POST.keys())}")
        return super().dispatch(request, *args, **kwargs)


    def get_form(self, form_class=None):
        form = super().get_form(form_class)
        # Forzar valores iniciales para campos requeridos
        config = self.get_object()
        print(f"DEBUG: Config object: {config}")
        print(f"DEBUG: feedback_retrain_threshold value: {config.feedback_retrain_threshold}")

        initial_data = {
            'adoption_phase': config.adoption_phase or 'passive',
            'auto_analysis_enabled': config.auto_analysis_enabled,
            'analysis_interval_hours': config.analysis_interval_hours or 24,
            'anomaly_threshold': config.anomaly_threshold or 0.1,
            'min_confidence_score': config.min_confidence_score or 0.7,
            'max_incidents_per_hour': config.max_incidents_per_hour or 10,
            'max_predictions_per_hour': config.max_predictions_per_hour or 50,
            'circuit_breaker_threshold': config.circuit_breaker_threshold or 0.3,
            'circuit_breaker_enabled': config.circuit_breaker_enabled,
            'require_human_approval': config.require_human_approval,
            'auto_create_incidents': config.auto_create_incidents,
            'auto_apply_measures': config.auto_apply_measures,
            'learning_enabled': config.learning_enabled,
            'feedback_retrain_threshold': config.feedback_retrain_threshold or 10,
            'adaptive_thresholds': config.adaptive_thresholds,
            'enable_performance_alerts': config.enable_performance_alerts,
            'enable_anomaly_alerts': config.enable_anomaly_alerts,
            'alert_email_recipients': json.dumps(config.alert_email_recipients or []),
            'enable_deep_learning': config.enable_deep_learning,
            'enable_external_integrations': config.enable_external_integrations,
            'correlation_time_window': config.correlation_time_window or 30
        }
        print(f"DEBUG: Setting initial feedback_retrain_threshold: {initial_data['feedback_retrain_threshold']}")
        form.initial = initial_data
        return form

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Agregar opciones de campos para el template
        context['adoption_phase_choices'] = AIConfiguration._meta.get_field('adoption_phase').choices
        return context

    def get_object(self, queryset=None):
        # Siempre devolver la primera configuración o crear una nueva con valores por defecto
        config = AIConfiguration.objects.first()
        if not config:
            # Crear nueva configuración con todos los valores por defecto
            config = AIConfiguration.objects.create(
                adoption_phase='passive',
                max_predictions_per_hour=50,
                circuit_breaker_threshold=0.3,
                circuit_breaker_enabled=True,
                auto_create_incidents=False,
                auto_apply_measures=False,
                adaptive_thresholds=True,
                enable_performance_alerts=True,
                enable_anomaly_alerts=True,
                alert_email_recipients=[],
                enable_deep_learning=False,
                enable_external_integrations=False,
                correlation_time_window=30
            )
            print(f"DEBUG: Created new AIConfiguration: {config}")
            logger.info("Created new AIConfiguration with default values")
        else:
            # Verificar y actualizar campos que puedan estar vacíos
            updated = False
            defaults = {
                'adoption_phase': 'passive',
                'max_predictions_per_hour': 50,
                'circuit_breaker_threshold': 0.3,
                'circuit_breaker_enabled': True,
                'auto_create_incidents': False,
                'auto_apply_measures': False,
                'adaptive_thresholds': True,
                'enable_performance_alerts': True,
                'enable_anomaly_alerts': True,
                'alert_email_recipients': [],
                'enable_deep_learning': False,
                'enable_external_integrations': False,
                'correlation_time_window': 30
            }

            for field, default_value in defaults.items():
                current_value = getattr(config, field, None)
                if current_value is None or (isinstance(current_value, str) and current_value == ''):
                    setattr(config, field, default_value)
                    updated = True
                    print(f"DEBUG: Updated field {field} to default value {default_value}")
                    logger.info(f"Updated field {field} to default value {default_value}")

            if updated:
                config.save()
                print(f"DEBUG: Saved updated config: {config}")
                logger.info("Updated existing AIConfiguration with missing default values")

        print(f"DEBUG: Returning config: {config}")
        print(f"DEBUG: Config alert_email_recipients: {config.alert_email_recipients}")
        return config

    def form_valid(self, form):
        print(f"DEBUG: Form instance: {form.instance}")
        print(f"DEBUG: Form cleaned_data keys: {list(form.cleaned_data.keys())}")
        print(f"DEBUG: alert_email_recipients value: {form.cleaned_data.get('alert_email_recipients')}")

        # Guardar el formulario explícitamente
        try:
            self.object = form.save()
            print(f"DEBUG: Configuration saved successfully: {self.object}")

            # Log de auditoría
            AIAuditLog.objects.create(
                action_type='configuration_changed',
                severity='info',
                description='Configuración de IRIS actualizada por usuario',
                user=self.request.user if self.request.user.is_authenticated else None,
                metadata={
                    'adoption_phase': self.object.adoption_phase,
                    'auto_analysis_enabled': self.object.auto_analysis_enabled,
                    'changes': 'Configuración actualizada'
                }
            )

            messages.success(self.request, '✅ Configuración de IRIS guardada exitosamente. Los cambios han sido aplicados.')
            return super().form_valid(form)

        except Exception as e:
            print(f"DEBUG: Error saving configuration: {str(e)}")
            messages.error(self.request, f'❌ Error al guardar la configuración: {str(e)}')
            return self.form_invalid(form)

    def form_invalid(self, form):
        # Log form errors for debugging
        print(f"DEBUG: Form is invalid: {form.errors}")
        print(f"DEBUG: Non-field errors: {form.non_field_errors()}")
        logger.error(f"Form is invalid: {form.errors}")
        logger.error(f"Non-field errors: {form.non_field_errors()}")
        messages.error(self.request, f'❌ Errores en el formulario: {form.errors}')
        return super().form_invalid(form)

    def get(self, request, *args, **kwargs):
        print("DEBUG: GET request to AIConfigurationUpdateView")
        return super().get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        print("DEBUG: POST request to AIConfigurationUpdateView")
        return super().post(request, *args, **kwargs)

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

@login_required
def acknowledge_alert(request, alert_id):
    """Reconocer una alerta"""
    if request.method == 'POST':
        try:
            alert = AIAlert.objects.get(id=alert_id)
            alert.acknowledge(request.user)

            # Log de auditoría
            AIAuditLog.objects.create(
                action_type='alert_acknowledged',
                severity='info',
                description=f'Alerta reconocida: {alert.title}',
                user=request.user,
                metadata={'alert_id': alert_id, 'alert_title': alert.title}
            )

            return JsonResponse({'success': True})
        except AIAlert.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Alerta no encontrada'}, status=404)
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)
    return JsonResponse({'success': False, 'error': 'Método no permitido'}, status=405)
