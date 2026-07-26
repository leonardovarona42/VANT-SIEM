import json

from rest_framework import serializers

from .models import DlpPolicy, DlpRule, DlpThreat, DlpScanSummary


class DlpRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = DlpRule
        fields = [
            "id", "name", "pattern", "match_type", "classification",
            "severity", "tags", "is_active",
        ]


class DlpPolicySerializer(serializers.ModelSerializer):
    rules = DlpRuleSerializer(many=True, read_only=True)

    class Meta:
        model = DlpPolicy
        fields = [
            "code", "name", "description", "is_active", "severity",
            "scan_mode", "scan_paths", "monitored_extensions", "max_file_size_mb",
            "max_scan_seconds", "target_os", "realtime_enabled", "rules", "updated_at",
        ]


class DlpThreatListSerializer(serializers.ModelSerializer):
    class Meta:
        model = DlpThreat
        fields = [
            "id", "fingerprint", "agent_id", "agent_hostname", "policy_code",
            "rule_name", "classification", "severity", "status", "file_name",
            "file_path", "actor", "channel", "summary", "detected_at", "created_at",
        ]


class DlpThreatDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = DlpThreat
        fields = "__all__"
        read_only_fields = ["fingerprint", "created_at", "event_published"]


class DlpThreatIngestSerializer(serializers.Serializer):
    agent_id = serializers.CharField(required=False, default="")
    incidents = serializers.ListField(child=serializers.DictField())

    def validate_incidents(self, value):
        for item in value:
            if not item.get("fingerprint"):
                raise serializers.ValidationError("Each incident must have a 'fingerprint'")
        return value


class DlpThreatIngestMultipartSerializer(serializers.Serializer):
    metadata = serializers.CharField(required=True)

    def validate_metadata(self, value):
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError as e:
                raise serializers.ValidationError(f"Invalid JSON: {e}")
        if not isinstance(value, dict):
            raise serializers.ValidationError("metadata must be a JSON object")
        if "incidents" not in value or not isinstance(value["incidents"], list):
            raise serializers.ValidationError("metadata must contain 'incidents' list")
        for item in value["incidents"]:
            if not item.get("fingerprint"):
                raise serializers.ValidationError("Each incident must have a 'fingerprint'")
        return value


class DlpScanSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = DlpScanSummary
        fields = "__all__"


class DlpAgentConfigSerializer(serializers.Serializer):
    policies = DlpPolicySerializer(many=True)
    fetched_at = serializers.DateTimeField(required=False)
