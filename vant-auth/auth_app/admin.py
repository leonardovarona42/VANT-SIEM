from django.contrib import admin
from auth_app.models import AuthUser, AuthAgentToken, AuthAuditLog


@admin.register(AuthUser)
class AuthUserAdmin(admin.ModelAdmin):
    list_display = ("username", "email", "role", "is_active", "created_at")
    search_fields = ("username", "email")
    list_filter = ("role", "is_active")


@admin.register(AuthAgentToken)
class AuthAgentTokenAdmin(admin.ModelAdmin):
    list_display = ("agent_id", "hostname", "is_active", "created_at", "last_used")
    search_fields = ("agent_id", "hostname")
    list_filter = ("is_active",)


@admin.register(AuthAuditLog)
class AuthAuditLogAdmin(admin.ModelAdmin):
    list_display = ("event", "user_id", "agent_id", "ip_address", "created_at")
    search_fields = ("event", "user_id", "agent_id")
    list_filter = ("event",)
    readonly_fields = ("event", "user_id", "agent_id", "ip_address", "details", "created_at")
