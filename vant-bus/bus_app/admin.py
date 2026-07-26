from django.contrib import admin

from bus_app.models import AlertChannel, AlertHistory


@admin.register(AlertChannel)
class AlertChannelAdmin(admin.ModelAdmin):
    list_display = ("name", "channel_type", "is_active", "created_at")
    list_filter = ("channel_type", "is_active")
    search_fields = ("name",)


@admin.register(AlertHistory)
class AlertHistoryAdmin(admin.ModelAdmin):
    list_display = ("severity", "title", "source", "channel", "status", "sent_at")
    list_filter = ("severity", "channel", "status")
    search_fields = ("title", "message")
    readonly_fields = ("sent_at",)
