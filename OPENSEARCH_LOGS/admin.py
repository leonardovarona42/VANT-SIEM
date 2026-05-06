from django.contrib import admin
from .models import LogEvent, LogSource, LogRetentionPolicy

@admin.register(LogEvent)
class LogEventAdmin(admin.ModelAdmin):
    list_display = ('event_time', 'source_type', 'severity', 'event_category', 'host_ip', 'ingested_at')
    list_filter = ('source_type', 'severity', 'event_category')
    search_fields = ('message', 'host_ip', 'source_type')
    date_hierarchy = 'event_time'
    raw_id_fields = ('source',)

@admin.register(LogSource)
class LogSourceAdmin(admin.ModelAdmin):
    list_display = ('source_id', 'source_type', 'vendor', 'host_ip', 'protocol', 'enabled', 'last_seen_at')
    list_filter = ('source_type', 'vendor', 'protocol', 'enabled')
    search_fields = ('source_id', 'host_name', 'host_ip')

@admin.register(LogRetentionPolicy)
class LogRetentionPolicyAdmin(admin.ModelAdmin):
    list_display = ('source_type', 'retention_days', 'auto_delete', 'last_cleanup_at')
    list_filter = ('auto_delete',)
