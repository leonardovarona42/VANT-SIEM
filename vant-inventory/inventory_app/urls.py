from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    health_check, dashboard_stats, register_agent, heartbeat, submit_inventory,
    command_result, screen_upload, screen_latest, processes_upload, processes_latest,
    AgentViewSet, SoftwareViewSet, AgentCommandViewSet,
    pull_commands, send_command, delete_agent,
    services_report, services_list, services_toggle,
)

router = DefaultRouter()
router.register(r'api/agents', AgentViewSet, basename='agent')
router.register(r'api/software', SoftwareViewSet, basename='software')
router.register(r'api/commands', AgentCommandViewSet, basename='command')

urlpatterns = [
    path('api/health/', health_check, name='inventory-api-health'),
    path('api/stats/dashboard/', dashboard_stats, name='inventory-api-dashboard-stats'),
    path('api/register/', register_agent, name='inventory-api-register'),
    path('api/heartbeat/', heartbeat, name='inventory-api-heartbeat'),
    path('api/inventory/submit/', submit_inventory, name='inventory-api-submit'),
    path('api/command-result/', command_result, name='inventory-api-command-result'),
    path('api/screen/upload/', screen_upload, name='inventory-api-screen-upload'),
    path('api/screen/latest/<str:agent_id>/', screen_latest, name='inventory-api-screen-latest'),
    path('api/processes/upload/', processes_upload, name='inventory-api-processes-upload'),
    path('api/processes/latest/<str:agent_id>/', processes_latest, name='inventory-api-processes-latest'),
    path('api/commands/pull/', pull_commands, name='inventory-api-pull-commands'),
    path('api/agents/<str:agent_id>/command/', send_command, name='inventory-api-send-command'),
    path('api/agents/<str:agent_id>/delete/', delete_agent, name='inventory-api-delete-agent'),
    path('api/agents/<str:agent_id>/services/report/', services_report, name='inventory-api-services-report'),
    path('api/agents/<str:agent_id>/services/', services_list, name='inventory-api-services-list'),
    path('api/agents/<str:agent_id>/services/toggle/', services_toggle, name='inventory-api-services-toggle'),
    path('', include(router.urls)),
]
