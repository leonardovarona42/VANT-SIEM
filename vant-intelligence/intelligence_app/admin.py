from django.contrib import admin
from .models import IntelligenceApiKey, IntelligenceIpReport, IntelligenceMacLookup, IntelligenceVtReport, IntelligenceScanJob

@admin.register(IntelligenceApiKey)
class IntelligenceApiKeyAdmin(admin.ModelAdmin):
    list_display = ('provider', 'enabled', 'quota_limit', 'quota_used', 'last_used_at')
    list_filter = ('provider', 'enabled')
    search_fields = ('provider',)

@admin.register(IntelligenceIpReport)
class IntelligenceIpReportAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'abuse_confidence_score', 'total_reports', 'country_code', 'queried_at')
    list_filter = ('is_whitelisted', 'country_code')
    search_fields = ('ip_address', 'domain')
    date_hierarchy = 'queried_at'

@admin.register(IntelligenceMacLookup)
class IntelligenceMacLookupAdmin(admin.ModelAdmin):
    list_display = ('mac_address', 'vendor', 'country', 'queried_at')
    search_fields = ('mac_address', 'vendor')

@admin.register(IntelligenceVtReport)
class IntelligenceVtReportAdmin(admin.ModelAdmin):
    list_display = ('indicator', 'indicator_type', 'malicious', 'suspicious', 'harmless', 'reputation_score', 'queried_at')
    list_filter = ('indicator_type',)
    search_fields = ('indicator',)
    date_hierarchy = 'queried_at'

@admin.register(IntelligenceScanJob)
class IntelligenceScanJobAdmin(admin.ModelAdmin):
    list_display = ('job_type', 'target', 'status', 'created_at', 'completed_at')
    list_filter = ('job_type', 'status')
    search_fields = ('target',)
