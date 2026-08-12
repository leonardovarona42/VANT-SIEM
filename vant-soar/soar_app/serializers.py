from rest_framework import serializers

from .models import (
    SoarConfig,
    SoarPrediction,
    SoarModel,
    ThreatPort,
    CriticalPort,
    NetworkFeature,
    FeedbackLabel,
    Playbook,
    PlaybookRun,
)


class SoarConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = SoarConfig
        fields = [
            "prediction_mode", "enabled", "report_threshold", "block_threshold",
            "high_threshold", "medium_threshold", "window_minutes",
            "burst_same_dst_threshold", "burst_targets_threshold",
            "report_informante", "create_report_in_soc", "auto_ack_after_days",
            "events_processed", "predictions_made", "last_run_at",
        ]


class ThreatPortSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThreatPort
        fields = "__all__"


class CriticalPortSerializer(serializers.ModelSerializer):
    class Meta:
        model = CriticalPort
        fields = "__all__"


class NetworkFeatureSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkFeature
        fields = [
            "id", "ip", "is_internal", "window_start", "window_end",
            "conn_count", "inbound_count", "outbound_count",
            "distinct_dst_ips", "distinct_dst_ports", "distinct_protos",
            "critical_port_access", "trojan_port_hit",
            "burst_same_dst", "burst_targets", "internal_targets", "external_targets",
            "syn_count", "abuse_score", "geo_country",
            "score", "risk_level", "updated_at",
        ]


class SoarPredictionSerializer(serializers.ModelSerializer):
    features = serializers.JSONField(read_only=True)

    class Meta:
        model = SoarPrediction
        fields = [
            "id", "ip", "score", "risk_level", "decision", "status",
            "model_version", "model_framework", "features", "evidence",
            "bus_event_id", "soc_report_id", "playbook_run_id",
            "created_at", "analyzed_at", "feedback_note",
        ]
        read_only_fields = fields


class SoarPredictionDetailSerializer(SoarPredictionSerializer):
    source_event_ids = serializers.JSONField(read_only=True)

    class Meta(SoarPredictionSerializer.Meta):
        fields = SoarPredictionSerializer.Meta.fields + ["source_event_ids"]


class FeedbackLabelSerializer(serializers.ModelSerializer):
    class Meta:
        model = FeedbackLabel
        fields = ["id", "prediction", "label", "notes", "created_by", "created_at"]


class SoarModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = SoarModel
        fields = [
            "id", "name", "framework", "version", "file_path", "metrics",
            "trained_samples", "feature_names", "is_active", "trained_at",
        ]


class PlaybookSerializer(serializers.ModelSerializer):
    class Meta:
        model = Playbook
        fields = "__all__"


class PlaybookRunSerializer(serializers.ModelSerializer):
    class Meta:
        model = PlaybookRun
        fields = "__all__"


class RetrainRequestSerializer(serializers.Serializer):
    model_name = serializers.CharField(default="incident_risk")
    samples = serializers.IntegerField(default=0, help_text="0 = usar todos los disponibles")


class FeedbackRequestSerializer(serializers.Serializer):
    label = serializers.ChoiceField(choices=["confirmed", "false_positive"])
    notes = serializers.CharField(required=False, allow_blank=True)
    created_by = serializers.CharField(required=False, allow_blank=True)


class ActOnPredictionRequestSerializer(serializers.Serializer):
    action = serializers.ChoiceField(choices=["block", "monitor", "investigate", "allow"])
