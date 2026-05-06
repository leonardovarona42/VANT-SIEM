from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    health_check, agent_stats, register_agent, heartbeat, submit_inventory,
    command_result, AgentViewSet, SoftwareViewSet, AgentCommandViewSet,
)
from .ui_views import inventory_dashboard, agents_list, agent_detail, software_list

router = DefaultRouter()
router.register(r'api/agents', AgentViewSet, basename='agent')
router.register(r'api/software', SoftwareViewSet, basename='software')
router.register(r'api/commands', AgentCommandViewSet, basename='command')

urlpatterns = [
    # UI
    path('', inventory_dashboard, name='inventory-dashboard'),
    path('agents/', agents_list, name='inventory-agents'),
    path('agent/<str:agent_id>/', agent_detail, name='inventory-agent-detail'),
    path('software/', software_list, name='inventory-software'),

    # API - Agent
    path('api/health/', health_check, name='inventory-api-health'),
    path('api/stats/', agent_stats, name='inventory-api-stats'),
    path('api/register/', register_agent, name='inventory-api-register'),
    path('api/heartbeat/', heartbeat, name='inventory-api-heartbeat'),
    path('api/inventory/submit/', submit_inventory, name='inventory-api-submit'),
    path('api/command-result/', command_result, name='inventory-api-command-result'),
    path('api/', include(router.urls)),
]
