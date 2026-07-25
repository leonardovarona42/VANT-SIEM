from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    health_check, agent_stats, register_agent, enroll_agent, request_bootstrap, heartbeat,
    submit_inventory, command_result, AgentViewSet, SoftwareViewSet, AgentCommandViewSet,
    push_config, get_agent_config, config_templates, delete_agent, send_command,
    pull_commands, screen_upload, screen_latest, processes_upload, processes_latest,
)
from .ui_views import inventory_dashboard, agents_list, agent_detail, software_list, agent_config_view, screen_viewer, request_services_list

router = DefaultRouter()
router.register(r'api/agents', AgentViewSet, basename='agent')
router.register(r'api/software', SoftwareViewSet, basename='software')
router.register(r'api/commands', AgentCommandViewSet, basename='command')

urlpatterns = [
    path('', inventory_dashboard, name='inventory-dashboard'),
    path('agents/', agents_list, name='inventory-agents'),
    path('agent/<str:agent_id>/', agent_detail, name='inventory-agent-detail'),
    path('agent/<str:agent_id>/screen/', screen_viewer, name='inventory-agent-screen'),
    path('agent/<str:agent_id>/config/', agent_config_view, name='inventory-agent-config'),
    path('agent/<str:agent_id>/services/list/', request_services_list, name='inventory-agent-services-list'),
    path('software/', software_list, name='inventory-software'),

    path('api/health/', health_check, name='inventory-api-health'),
    path('api/stats/', agent_stats, name='inventory-api-stats'),
    path('api/register/', register_agent, name='inventory-api-register'),
    path('api/agent/enroll/', enroll_agent, name='inventory-api-enroll'),
    path('api/agent/bootstrap/', request_bootstrap, name='inventory-api-bootstrap'),
    path('api/heartbeat/', heartbeat, name='inventory-api-heartbeat'),
    path('api/inventory/submit/', submit_inventory, name='inventory-api-submit'),
    path('api/command-result/', command_result, name='inventory-api-command-result'),
    path('api/config/templates/', config_templates, name='inventory-api-config-templates'),
    path('api/agent/<str:agent_id>/config/', get_agent_config, name='inventory-api-agent-config'),
    path('api/agent/<str:agent_id>/config/push/', push_config, name='inventory-api-config-push'),
    path('api/agent/<str:agent_id>/command/', send_command, name='inventory-api-send-command'),
    path('api/agent/commands/pull/', pull_commands, name='inventory-api-pull-commands'),
    path('api/screen/upload/', screen_upload, name='inventory-api-screen-upload'),
    path('api/screen/latest/<str:agent_id>/', screen_latest, name='inventory-api-screen-latest'),
    path('api/agent/processes/upload/', processes_upload, name='inventory-api-processes-upload'),
    path('api/agent/<str:agent_id>/processes/', processes_latest, name='inventory-api-processes-latest'),
    path('api/agent/<str:agent_id>/', delete_agent, name='inventory-api-delete-agent'),
    path('api/', include(router.urls)),
]
