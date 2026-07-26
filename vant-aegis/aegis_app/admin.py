from django.contrib import admin

from .models import DlpPolicy, DlpRule, DlpThreat, DlpScanSummary


class DlpRuleInline(admin.TabularInline):
    model = DlpRule
    extra = 0


@admin.register(DlpPolicy)
class DlpPolicyAdmin(admin.ModelAdmin):
    list_display = ["code", "name", "severity", "target_os", "is_active", "updated_at"]
    list_filter = ["is_active", "severity", "target_os", "scan_mode"]
    search_fields = ["code", "name", "description"]
    inlines = [DlpRuleInline]


@admin.register(DlpRule)
class DlpRuleAdmin(admin.ModelAdmin):
    list_display = ["name", "policy", "match_type", "classification", "severity", "is_active"]
    list_filter = ["match_type", "severity", "is_active"]
    search_fields = ["name", "pattern"]


@admin.register(DlpThreat)
class DlpThreatAdmin(admin.ModelAdmin):
    list_display = ["id", "fingerprint", "agent_hostname", "severity", "status", "file_name", "detected_at"]
    list_filter = ["severity", "status", "channel", "classification"]
    search_fields = ["fingerprint", "file_name", "file_path", "actor", "agent_id"]
    readonly_fields = ["fingerprint", "created_at", "event_published"]


@admin.register(DlpScanSummary)
class DlpScanSummaryAdmin(admin.ModelAdmin):
    list_display = ["id", "agent_hostname", "started_at", "files_scanned", "files_flagged", "status"]
    list_filter = ["status"]
    readonly_fields = ["created_at"]
