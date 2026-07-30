from rest_framework import serializers
from .models import (
    IntelligenceApiKey, IntelligenceIpReport,
    IntelligenceMacLookup, IntelligenceVtReport, IntelligenceScanJob,
)


class IntelligenceApiKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = IntelligenceApiKey
        fields = '__all__'
        read_only_fields = ('created_at', 'updated_at', 'last_used_at')
        extra_kwargs = {
            'api_key_encrypted': {'write_only': True},
        }


class IntelligenceApiKeyReadSerializer(serializers.ModelSerializer):
    class Meta:
        model = IntelligenceApiKey
        fields = ('id', 'provider', 'enabled', 'quota_limit', 'quota_used',
                  'quota_remaining', 'quota_reset_at', 'last_used_at', 'created_at')


class IntelligenceIpReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = IntelligenceIpReport
        fields = '__all__'


class IntelligenceIpLookupSerializer(serializers.Serializer):
    ip = serializers.CharField(required=True)


class IntelligenceMacLookupSerializer(serializers.ModelSerializer):
    class Meta:
        model = IntelligenceMacLookup
        fields = '__all__'


class IntelligenceMacLookupRequestSerializer(serializers.Serializer):
    mac = serializers.CharField(required=True)


class IntelligenceVtReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = IntelligenceVtReport
        fields = '__all__'


class IntelligenceVtLookupSerializer(serializers.Serializer):
    indicator = serializers.CharField(required=True)
    indicator_type = serializers.ChoiceField(
        choices=['ip', 'domain', 'url', 'hash'], required=True
    )


class IntelligenceScanJobSerializer(serializers.ModelSerializer):
    class Meta:
        model = IntelligenceScanJob
        fields = '__all__'
        read_only_fields = ('created_at', 'started_at', 'completed_at')


class IntelligenceScanJobCreateSerializer(serializers.Serializer):
    job_type = serializers.ChoiceField(choices=[
        'ip_enrich', 'domain_enrich', 'url_scan', 'hash_scan',
    ])
    target = serializers.CharField(required=True)
