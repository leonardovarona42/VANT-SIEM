from django.contrib import admin
from .models import (
    IDSIngestConfig, SnortLog, SuricataLog, IDSAlert, IDSStatistics,
    SuricataEveAlert, SuricataFlow, SuricataStats, SuricataSystemLog,
    SavedVisualization, SavedDashboard
)
@admin.register(SuricataEveAlert)
class SuricataEveAlertAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'event_type', 'src_ip', 'dest_ip', 'proto', 'signature_id', 'severity', 'category', 'action', 'created_at']
    list_filter = ['event_type', 'proto', 'severity', 'category', 'action', 'timestamp', 'created_at']
    search_fields = ['src_ip', 'dest_ip', 'message', 'signature_id', 'category']
    readonly_fields = ['created_at', 'log_hash']
    date_hierarchy = 'timestamp'
    ordering = ['-timestamp']

@admin.register(SuricataFlow)
class SuricataFlowAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'src_ip', 'dest_ip', 'src_port', 'dest_port', 'proto', 'app_proto', 'state', 'created_at']
    list_filter = ['proto', 'app_proto', 'state', 'timestamp', 'created_at']
    search_fields = ['src_ip', 'dest_ip', 'app_proto', 'state']
    readonly_fields = ['created_at', 'log_hash']
    date_hierarchy = 'timestamp'
    ordering = ['-timestamp']

@admin.register(SuricataStats)
class SuricataStatsAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'uptime', 'total_packets', 'total_bytes', 'packets_per_second', 'bytes_per_second', 'total_flows', 'total_alerts', 'created_at']
    list_filter = ['timestamp', 'created_at']
    search_fields = ['total_packets', 'total_bytes', 'total_alerts']
    readonly_fields = ['created_at', 'log_hash']
    date_hierarchy = 'timestamp'
    ordering = ['-timestamp']

@admin.register(SuricataSystemLog)
class SuricataSystemLogAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'level', 'component', 'message', 'created_at']
    list_filter = ['level', 'component', 'timestamp', 'created_at']
    search_fields = ['component', 'message', 'raw_line']
    readonly_fields = ['created_at', 'log_hash']
    date_hierarchy = 'timestamp'
    ordering = ['-timestamp']

@admin.register(IDSIngestConfig)
class IDSIngestConfigAdmin(admin.ModelAdmin):
    list_display = ['ids_type', 'log_path', 'active', 'retention_days', 'last_run', 'created_at']
    list_filter = ['ids_type', 'active', 'created_at']
    search_fields = ['log_path']
    readonly_fields = ['created_at', 'updated_at', 'last_position']
    fieldsets = (
        ('Configuración', {
            'fields': ('ids_type', 'log_path', 'active', 'retention_days')
        }),
        ('Estado', {
            'fields': ('last_run', 'last_position', 'created_at', 'updated_at')
        }),
    )

@admin.register(SnortLog)
class SnortLogAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'severity', 'src_ip', 'dst_ip', 'protocol', 'message_short', 'created_at']
    list_filter = ['severity', 'protocol', 'timestamp', 'created_at']
    search_fields = ['src_ip', 'dst_ip', 'message', 'raw']
    readonly_fields = ['created_at']
    date_hierarchy = 'timestamp'
    ordering = ['-timestamp']
    
    def message_short(self, obj):
        return obj.message[:50] + '...' if len(obj.message) > 50 else obj.message
    message_short.short_description = 'Mensaje'

@admin.register(SuricataLog)
class SuricataLogAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'severity', 'src_ip', 'dst_ip', 'protocol', 'message_short', 'created_at']
    list_filter = ['severity', 'protocol', 'timestamp', 'created_at']
    search_fields = ['src_ip', 'dst_ip', 'message', 'raw']
    readonly_fields = ['created_at']
    date_hierarchy = 'timestamp'
    ordering = ['-timestamp']
    
    def message_short(self, obj):
        return obj.message[:50] + '...' if len(obj.message) > 50 else obj.message
    message_short.short_description = 'Mensaje'

@admin.register(IDSAlert)
class IDSAlertAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'ids_type', 'severity', 'src_ip', 'dst_ip', 'acknowledged', 'acknowledged_by', 'created_at']
    list_filter = ['ids_type', 'severity', 'acknowledged', 'timestamp', 'created_at']
    search_fields = ['src_ip', 'dst_ip', 'message']
    readonly_fields = ['created_at']
    date_hierarchy = 'timestamp'
    ordering = ['-timestamp']
    
    fieldsets = (
        ('Información de la Alerta', {
            'fields': ('ids_type', 'log_id', 'severity', 'src_ip', 'dst_ip', 'message', 'timestamp')
        }),
        ('Estado', {
            'fields': ('acknowledged', 'acknowledged_by', 'acknowledged_at')
        }),
        ('Sistema', {
            'fields': ('created_at',)
        }),
    )

@admin.register(IDSStatistics)
class IDSStatisticsAdmin(admin.ModelAdmin):
    list_display = ['ids_type', 'date', 'total_events', 'critical_events', 'high_events', 'medium_events', 'low_events', 'created_at']
    list_filter = ['ids_type', 'date', 'created_at']
    search_fields = ['ids_type']
    readonly_fields = ['created_at']
    date_hierarchy = 'date'
    ordering = ['-date']
    
    fieldsets = (
        ('Información General', {
            'fields': ('ids_type', 'date', 'total_events')
        }),
        ('Distribución por Severidad', {
            'fields': ('critical_events', 'high_events', 'medium_events', 'low_events')
        }),
        ('Estadísticas Adicionales', {
            'fields': ('unique_src_ips', 'unique_dst_ips', 'top_protocols')
        }),
        ('Sistema', {
            'fields': ('created_at',)
        }),
    )


@admin.register(SavedVisualization)
class SavedVisualizationAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'space', 'owner', 'is_shared', 'updated_at']
    list_filter = ['space', 'is_shared', 'updated_at']
    search_fields = ['name', 'description', 'owner__username']
    readonly_fields = ['created_at', 'updated_at']
    ordering = ['-updated_at']


@admin.register(SavedDashboard)
class SavedDashboardAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'space', 'owner', 'is_shared', 'updated_at']
    list_filter = ['space', 'is_shared', 'updated_at']
    search_fields = ['name', 'description', 'owner__username']
    readonly_fields = ['created_at', 'updated_at']
    ordering = ['-updated_at']
