from django.contrib import admin

from .models import AgentDevice, AgentCommand, AgentInventorySnapshot


@admin.register(AgentDevice)
class AgentDeviceAdmin(admin.ModelAdmin):
    list_display = ("agent_id", "host_name", "host_ip", "agent_version", "status", "last_seen")
    search_fields = ("agent_id", "host_name", "host_ip")
    list_filter = ("status", "agent_version")


@admin.register(AgentCommand)
class AgentCommandAdmin(admin.ModelAdmin):
    list_display = ("agent", "command", "status", "created_at", "executed_at")
    list_filter = ("command", "status")


@admin.register(AgentInventorySnapshot)
class AgentInventorySnapshotAdmin(admin.ModelAdmin):
    list_display = ("agent", "created_at")
    search_fields = ("agent__agent_id", "agent__host_name")
