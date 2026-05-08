from rest_framework import serializers
from .models import DlpPolicy, DlpRule, DlpIncident, DlpScanSummary


class DlpRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = DlpRule
        fields = ['id', 'name', 'pattern', 'match_type', 'classification', 'severity', 'tags', 'enabled']


class DlpPolicySerializer(serializers.ModelSerializer):
    rules = DlpRuleSerializer(many=True, read_only=True)

    class Meta:
        model = DlpPolicy
        fields = ['id', 'code', 'name', 'description', 'enabled', 'severity',
                  'scan_paths', 'monitored_extensions', 'max_file_size_mb', 'rules',
                  'created_at', 'updated_at']


class DlpIncidentListSerializer(serializers.ModelSerializer):
    class Meta:
        model = DlpIncident
        fields = ['id', 'fingerprint', 'remote_agent_id', 'host_name', 'policy_code',
                  'rule_name', 'classification', 'severity', 'status', 'file_name',
                  'file_path', 'actor', 'channel', 'summary', 'detected_at', 'created_at']


class DlpIncidentDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = DlpIncident
        fields = '__all__'


class DlpIncidentIngestSerializer(serializers.Serializer):
    agent_id = serializers.CharField()
    incidents = serializers.ListField(child=serializers.DictField())


class DlpScanSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = DlpScanSummary
        fields = '__all__'


class DlpAgentConfigSerializer(serializers.Serializer):
    policies = DlpPolicySerializer(many=True)
