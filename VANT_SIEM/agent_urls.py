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
    path("authorize-stop/", views.agent_authorize_stop, name="agent-authorize-stop"),
]
