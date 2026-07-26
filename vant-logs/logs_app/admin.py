from django.contrib import admin
from .models import LogSource, LogEventRaw, LogRetentionPolicy


@admin.register(LogSource)
class LogSourceAdmin(admin.ModelAdmin):
    list_display = ('source_id', 'source_type', 'vendor', 'host_ip', 'enabled', 'last_seen_at')
    list_filter = ('source_type', 'enabled', 'protocol')
    search_fields = ('source_id', 'host_name', 'host_ip')
    readonly_fields = ('registered_at', 'last_seen_at')


@admin.register(LogEventRaw)
class LogEventRawAdmin(admin.ModelAdmin):
    list_display = ('id', 'source_type', 'host_ip', 'severity', 'event_category', 'event_time', 'ingested_at')
    list_filter = ('severity', 'source_type', 'event_category')
    search_fields = ('message', 'host_name', 'host_ip')
    readonly_fields = ('ingested_at',)
    date_hierarchy = 'event_time'


@admin.register(LogRetentionPolicy)
class LogRetentionPolicyAdmin(admin.ModelAdmin):
    list_display = ('source_type', 'retention_days', 'auto_delete', 'last_cleanup_at')
    list_filter = ('auto_delete',)
