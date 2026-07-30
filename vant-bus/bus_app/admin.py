from django.contrib import admin

from bus_app.models import (
    AlertChannel,
    AlertHistory,
    EmailConfig,
    GroupAlertSubscription,
    GroupMember,
    NotificationGroup,
    NotificationLog,
    ServiceConfig,
    ServiceHealthLog,
    SystemEvent,
)


@admin.register(SystemEvent)
class SystemEventAdmin(admin.ModelAdmin):
    list_display = ("event_type", "source_service", "entity_type", "severity", "created_at")
    list_filter = ("event_type", "source_service", "severity")
    search_fields = ("actor_username", "entity_id")


@admin.register(NotificationGroup)
class NotificationGroupAdmin(admin.ModelAdmin):
    list_display = ("name", "is_active", "created_at")


@admin.register(GroupMember)
class GroupMemberAdmin(admin.ModelAdmin):
    list_display = ("username", "group", "added_at")
    list_filter = ("group",)


@admin.register(GroupAlertSubscription)
class GroupAlertSubscriptionAdmin(admin.ModelAdmin):
    list_display = ("group", "event_type", "channel", "is_active")


@admin.register(NotificationLog)
class NotificationLogAdmin(admin.ModelAdmin):
    list_display = ("event", "group", "channel", "status", "created_at")
    list_filter = ("status", "channel")


@admin.register(ServiceConfig)
class ServiceConfigAdmin(admin.ModelAdmin):
    list_display = ("display_name", "name", "port", "last_health_status", "is_active")


@admin.register(ServiceHealthLog)
class ServiceHealthLogAdmin(admin.ModelAdmin):
    list_display = ("service", "status", "response_time_ms", "checked_at")


@admin.register(AlertChannel)
class AlertChannelAdmin(admin.ModelAdmin):
    list_display = ("name", "channel_type", "is_active", "created_at")


@admin.register(AlertHistory)
class AlertHistoryAdmin(admin.ModelAdmin):
    list_display = ("severity", "title", "source", "channel", "status", "sent_at")


@admin.register(EmailConfig)
class EmailConfigAdmin(admin.ModelAdmin):
    list_display = ("smtp_host", "smtp_port", "from_address", "is_active")
