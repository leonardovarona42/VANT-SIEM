from django.urls import path

from . import views


urlpatterns = [
    path("enroll/", views.agent_enroll, name="agent-enroll"),
    path("bootstrap/", views.agent_bootstrap_secret, name="agent-bootstrap"),
    path("heartbeat/", views.agent_heartbeat, name="agent-heartbeat"),
    path("inventory/", views.agent_inventory, name="agent-inventory"),
    path("commands/pull/", views.agent_commands_pull, name="agent-commands-pull"),
    path("commands/ack/", views.agent_commands_ack, name="agent-commands-ack"),
    path("commands/issue/", views.agent_command_issue, name="agent-command-issue"),
    path("list/", views.agent_list, name="agent-list"),
    path("detail/<str:agent_id>/", views.agent_detail, name="agent-detail"),
    path("inventory/export/<str:agent_id>/", views.agent_inventory_csv, name="agent-inventory-csv"),
    path("inventory/apps/export/<str:agent_id>/", views.agent_apps_csv, name="agent-apps-csv"),
    path("inventory/compare/<str:agent_id>/", views.agent_inventory_compare, name="agent-inventory-compare"),
    path("authorize-stop/", views.agent_authorize_stop, name="agent-authorize-stop"),
]
