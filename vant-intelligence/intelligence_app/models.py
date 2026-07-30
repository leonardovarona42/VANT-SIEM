import logging
from django.db import models
from django.utils import timezone

logger = logging.getLogger(__name__)


class IntelligenceApiKey(models.Model):
    PROVIDER_CHOICES = [
        ('abuseipdb', 'AbuseIPDB'),
        ('macvendors', 'MAC Vendors'),
        ('virustotal', 'VirusTotal'),
    ]
    provider = models.CharField(max_length=32, choices=PROVIDER_CHOICES, unique=True)
    api_key_encrypted = models.TextField()
    enabled = models.BooleanField(default=True)
    quota_limit = models.IntegerField(default=0, help_text="Daily quota limit (0 = unlimited)")
    quota_used = models.IntegerField(default=0)
    quota_reset_at = models.DateTimeField(blank=True, null=True)
    last_used_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'intelligence_api_keys'
        verbose_name = 'API Key'
        verbose_name_plural = 'API Keys'

    def __str__(self):
        return f'{self.get_provider_display()}'

    @property
    def quota_remaining(self):
        if self.quota_limit <= 0:
            return -1
        return max(self.quota_limit - self.quota_used, 0)

    @property
    def is_quota_exhausted(self):
        if self.quota_limit <= 0:
            return False
        return self.quota_used >= self.quota_limit


class IntelligenceIpReport(models.Model):
    ip_address = models.GenericIPAddressField(db_index=True)
    is_whitelisted = models.BooleanField(default=False)
    abuse_confidence_score = models.IntegerField(default=0)
    country_code = models.CharField(max_length=4, blank=True, default='')
    country_name = models.CharField(max_length=128, blank=True, default='')
    domain = models.CharField(max_length=255, blank=True, default='')
    total_reports = models.IntegerField(default=0)
    num_distinct_users = models.IntegerField(default=0)
    last_reported_at = models.DateTimeField(blank=True, null=True)
    reports = models.JSONField(default=list, blank=True)
    queried_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'intelligence_ip_reports'
        verbose_name = 'IP Report'
        verbose_name_plural = 'IP Reports'
        indexes = [
            models.Index(fields=['ip_address', '-queried_at']),
        ]

    def __str__(self):
        return f'{self.ip_address} (score={self.abuse_confidence_score})'


class IntelligenceMacLookup(models.Model):
    mac_address = models.CharField(max_length=17, db_index=True)
    vendor = models.CharField(max_length=255, blank=True, default='')
    country = models.CharField(max_length=128, blank=True, default='')
    is_private = models.BooleanField(default=False)
    queried_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'intelligence_mac_lookups'
        verbose_name = 'MAC Lookup'
        verbose_name_plural = 'MAC Lookups'
        indexes = [
            models.Index(fields=['mac_address', '-queried_at']),
        ]

    def __str__(self):
        return f'{self.mac_address} -> {self.vendor}'


class IntelligenceVtReport(models.Model):
    INDICATOR_CHOICES = [
        ('ip', 'IP Address'),
        ('domain', 'Domain'),
        ('url', 'URL'),
        ('hash', 'File Hash'),
    ]
    indicator = models.CharField(max_length=1024, db_index=True)
    indicator_type = models.CharField(max_length=16, choices=INDICATOR_CHOICES)
    malicious = models.IntegerField(default=0)
    suspicious = models.IntegerField(default=0)
    harmless = models.IntegerField(default=0)
    undetected = models.IntegerField(default=0)
    timeout = models.IntegerField(default=0)
    last_analysis_stats = models.JSONField(default=dict, blank=True)
    reputation_score = models.IntegerField(default=0, help_text="-100 to 100")
    verbose_msg = models.TextField(blank=True, default='')
    queried_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'intelligence_vt_reports'
        verbose_name = 'VirusTotal Report'
        verbose_name_plural = 'VirusTotal Reports'
        indexes = [
            models.Index(fields=['indicator', '-queried_at']),
            models.Index(fields=['indicator_type', 'malicious']),
        ]

    def __str__(self):
        return f'{self.indicator_type}:{self.indicator} (malicious={self.malicious})'


class IntelligenceScanJob(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    JOB_TYPE_CHOICES = [
        ('ip_enrich', 'IP Enrichment'),
        ('domain_enrich', 'Domain Enrichment'),
        ('url_scan', 'URL Scan'),
        ('hash_scan', 'File Hash Scan'),
        ('soar_playbook', 'SOAR Playbook'),
    ]
    job_type = models.CharField(max_length=32, choices=JOB_TYPE_CHOICES)
    target = models.CharField(max_length=1024, help_text="IP, domain, URL or hash")
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default='pending')
    result = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(blank=True, null=True)
    completed_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = 'intelligence_scan_jobs'
        verbose_name = 'Scan Job'
        verbose_name_plural = 'Scan Jobs'
        indexes = [
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['job_type']),
        ]

    def __str__(self):
        return f'{self.get_job_type_display()} {self.target} [{self.status}]'
