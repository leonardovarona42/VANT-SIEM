from django.contrib import admin

from .models import (
    AegisDlpIncident,
    AegisDlpPolicy,
    AegisDlpRule,
    AgentCommand,
    AgentDevice,
    AgentHardwareComponent,
    AgentInventorySnapshot,
    AgentNetworkIdentity,
    AgentSoftwareRecord,
    AgentTimelineEvent,
)


@admin.register(AgentDevice)
class AgentDeviceAdmin(admin.ModelAdmin):
    list_display = ("agent_id", "host_name", "host_ip", "agent_version", "status", "last_seen", "last_inventory_at", "last_dlp_at")
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


@admin.register(AgentTimelineEvent)
class AgentTimelineEventAdmin(admin.ModelAdmin):
    list_display = ("agent", "category", "event_type", "severity", "observed_at")
    list_filter = ("category", "severity", "source_service")
    search_fields = ("agent__agent_id", "title", "description", "actor", "file_path")


@admin.register(AgentHardwareComponent)
class AgentHardwareComponentAdmin(admin.ModelAdmin):
    list_display = ("agent", "component_type", "name", "serial_number", "status", "last_seen")
    list_filter = ("component_type", "status")
    search_fields = ("agent__agent_id", "name", "serial_number", "model", "vendor")


@admin.register(AgentSoftwareRecord)
class AgentSoftwareRecordAdmin(admin.ModelAdmin):
    list_display = ("agent", "name", "version", "publisher", "is_present", "last_seen")
    list_filter = ("is_present", "publisher")
    search_fields = ("agent__agent_id", "name", "version", "publisher")


@admin.register(AgentNetworkIdentity)
class AgentNetworkIdentityAdmin(admin.ModelAdmin):
    list_display = ("agent", "address_type", "address", "mac_address", "interface_name", "is_active")
    list_filter = ("address_type", "is_active")
    search_fields = ("agent__agent_id", "address", "mac_address", "interface_name")


class AegisDlpRuleInline(admin.TabularInline):
    model = AegisDlpRule
    extra = 0


@admin.register(AegisDlpPolicy)
class AegisDlpPolicyAdmin(admin.ModelAdmin):
    list_display = ("name", "code", "enabled", "severity", "updated_at")
    list_filter = ("enabled", "severity")
    search_fields = ("name", "code", "description")
    inlines = [AegisDlpRuleInline]


@admin.register(AegisDlpIncident)
class AegisDlpIncidentAdmin(admin.ModelAdmin):
    list_display = ("agent", "classification", "severity", "file_name", "actor", "detected_at", "status")
    list_filter = ("classification", "severity", "status")
    search_fields = ("agent__agent_id", "file_name", "file_path", "actor", "file_hash")
