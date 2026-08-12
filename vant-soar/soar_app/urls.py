from django.urls import path

from . import views

urlpatterns = [
    path("config/", views.config_view, name="soar-config"),
    path("threat-ports/", views.threat_ports_view, name="soar-threat-ports"),
    path("critical-ports/", views.critical_ports_view, name="soar-critical-ports"),
    path("predictions/", views.predictions_view, name="soar-predictions"),
    path("predictions/<int:pk>/", views.prediction_detail, name="soar-prediction-detail"),
    path("predictions/<int:pk>/feedback/", views.prediction_feedback, name="soar-prediction-feedback"),
    path("predictions/<int:pk>/act/", views.prediction_act, name="soar-prediction-act"),
    path("features/", views.features_view, name="soar-features"),
    path("models/", views.models_view, name="soar-models"),
    path("playbooks/", views.playbooks_view, name="soar-playbooks"),
    path("playbook-runs/", views.playbook_runs_view, name="soar-playbook-runs"),
    path("stats/", views.stats_view, name="soar-stats"),
    path("analyze/", views.analyze_now_view, name="soar-analyze"),
    path("retrain/", views.retrain_view, name="soar-retrain"),
]
