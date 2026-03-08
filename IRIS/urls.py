from django.urls import path
from . import views

app_name = 'iris'

urlpatterns = [
    # Dashboard principal
    path('', views.AIDashboardView.as_view(), name='iris_dashboard'),

    # Análisis y operaciones
    path('run-analysis/', views.AIAnalysisCreateView.as_view(), name='run_ai_analysis'),
    path('train-models/', views.train_models, name='train_models'),

    # Feedback humano
    path('feedback/<int:incident_id>/', views.human_feedback, name='human_feedback'),

    # Predicciones
    path('predictions/', views.IncidentPredictionListView.as_view(), name='iris_predictions'),
    path('predictions/<int:prediction_id>/validate/', views.validate_prediction, name='validate_prediction'),

    # Configuración
    path('configuration/', views.AIConfigurationUpdateView.as_view(), name='iris_configuration'),

    # Reportes
    path('performance/', views.performance_report, name='performance_report'),

    # Live AI Activity Monitor
    path('live/', views.live_ai_monitor, name='live_ai_monitor'),

    # Alert Management
    path('acknowledge-alert/<int:alert_id>/', views.acknowledge_alert, name='acknowledge_alert'),
]