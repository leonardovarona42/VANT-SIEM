from django.contrib import admin

from .models import DlpPolicy, DlpRule, DlpThreat


class DlpRuleInline(admin.TabularInline):
    model = DlpRule
    extra = 1
    fields = ["name", "classification", "severity", "match_type", "pattern", "is_active"]


@admin.register(DlpPolicy)
class DlpPolicyAdmin(admin.ModelAdmin):
    list_display = ["code", "name", "severity", "is_active", "target_os", "updated_at"]
    list_filter = ["is_active", "severity", "target_os"]
    search_fields = ["code", "name", "description"]
    prepopulated_fields = {"code": ("name",)}
    inlines = [DlpRuleInline]


@admin.register(DlpRule)
class DlpRuleAdmin(admin.ModelAdmin):
    list_display = ["name", "policy", "classification", "severity", "match_type", "is_active"]
    list_filter = ["match_type", "severity", "is_active", "policy"]
    search_fields = ["name", "classification", "pattern"]


@admin.register(DlpThreat)
class DlpThreatAdmin(admin.ModelAdmin):
    list_display = [
        "fingerprint_short", "severity", "file_name", "channel",
        "agent_hostname", "classification", "detected_at",
    ]
    list_filter = ["severity", "channel", "classification"]
    search_fields = ["file_name", "file_path", "actor", "agent_hostname", "summary"]
    readonly_fields = ["fingerprint", "created_at", "event_published"]
    date_hierarchy = "detected_at"

    def fingerprint_short(self, obj):
        return obj.fingerprint[:16] + "..." if len(obj.fingerprint) > 16 else obj.fingerprint

    fingerprint_short.short_description = "Fingerprint"
