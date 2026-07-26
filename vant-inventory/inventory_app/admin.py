from django.contrib import admin
from .models import Agent, HardwareInventory, SoftwareInventory, AgentCommand, ScreenCapture, ProcessSnapshot


@admin.register(Agent)
class AgentAdmin(admin.ModelAdmin):
    list_display = (
        'agent_id', 'hostname', 'machine_name', 'os_type', 'os_version',
        'ip_address', 'mac_address', 'status', 'last_heartbeat', 'registered_at',
    )
    search_fields = ('agent_id', 'hostname', 'machine_name', 'ip_address', 'mac_address')
    list_filter = ('status', 'os_type', 'agent_version')
    readonly_fields = ('agent_id', 'registered_at', 'updated_at')


@admin.register(HardwareInventory)
class HardwareInventoryAdmin(admin.ModelAdmin):
    list_display = ('agent', 'cpu_model', 'cpu_cores', 'ram_total_gb', 'serial_number', 'last_updated')
    search_fields = ('agent__hostname', 'serial_number', 'manufacturer', 'product_name')
    readonly_fields = ('last_updated',)


@admin.register(SoftwareInventory)
class SoftwareInventoryAdmin(admin.ModelAdmin):
    list_display = ('agent', 'name', 'version', 'publisher', 'software_type', 'is_system', 'last_seen_at')
    search_fields = ('agent__hostname', 'name', 'publisher')
    list_filter = ('software_type', 'is_system')
    readonly_fields = ('last_seen_at',)


@admin.register(AgentCommand)
class AgentCommandAdmin(admin.ModelAdmin):
    list_display = ('command_id', 'agent', 'command_type', 'status', 'created_at', 'sent_at', 'completed_at')
    search_fields = ('command_id', 'agent__hostname')
    list_filter = ('command_type', 'status')
    readonly_fields = ('command_id', 'created_at', 'sent_at', 'completed_at')


@admin.register(ScreenCapture)
class ScreenCaptureAdmin(admin.ModelAdmin):
    list_display = ('agent', 'captured_at')
    search_fields = ('agent__hostname',)
    readonly_fields = ('captured_at',)


@admin.register(ProcessSnapshot)
class ProcessSnapshotAdmin(admin.ModelAdmin):
    list_display = ('agent', 'captured_at')
    search_fields = ('agent__hostname',)
    readonly_fields = ('captured_at',)
