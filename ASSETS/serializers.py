from rest_framework import serializers

from .models import DlpPolicy, DlpRule, DlpThreat


# ---------------------------------------------------------------------------
# DLP Policy + Rule serializers
# ---------------------------------------------------------------------------

class DlpRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = DlpRule
        fields = [
            "id", "name", "classification", "severity",
            "match_type", "pattern", "is_active",
        ]


class DlpPolicySerializer(serializers.ModelSerializer):
    rules = DlpRuleSerializer(many=True, read_only=True)

    class Meta:
        model = DlpPolicy
        fields = [
            "code", "name", "description", "severity", "is_active",
            "scan_paths", "monitored_extensions",
            "max_file_size_mb", "max_scan_seconds", "target_os",
            "rules", "updated_at",
        ]


# ---------------------------------------------------------------------------
# DLP Threat serializers
# ---------------------------------------------------------------------------

class DlpThreatSerializer(serializers.ModelSerializer):
    class Meta:
        model = DlpThreat
        fields = "__all__"
        read_only_fields = ["fingerprint", "created_at", "event_published"]


class DlpThreatSubmitSerializer(serializers.Serializer):
    """Serializer for agent threat submissions (batch)."""

    incidents = serializers.ListField(
        child=serializers.JSONField(), min_length=1,
        help_text="List of DLP detection dicts (fingerprint required)",
    )
    agent_id = serializers.UUIDField(required=False)

    def validate_incidents(self, value):
        for item in value:
            if not item.get("fingerprint"):
                raise serializers.ValidationError("Each incident must have a 'fingerprint'")
        return value
