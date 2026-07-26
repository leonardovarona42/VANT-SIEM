from rest_framework import serializers

from bus_app.models import AlertChannel, AlertHistory


class AlertChannelSerializer(serializers.ModelSerializer):
    class Meta:
        model = AlertChannel
        fields = [
            "id",
            "name",
            "channel_type",
            "config",
            "is_active",
            "severity_filter",
            "created_at",
        ]
        read_only_fields = ["id", "created_at"]


class AlertHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = AlertHistory
        fields = [
            "id",
            "severity",
            "title",
            "message",
            "source",
            "channel",
            "status",
            "metadata",
            "sent_at",
        ]
        read_only_fields = ["id", "sent_at"]


class SendAlertSerializer(serializers.Serializer):
    severity = serializers.ChoiceField(
        choices=["critical", "high", "medium", "low", "info"]
    )
    title = serializers.CharField(max_length=255)
    message = serializers.CharField()
    source = serializers.CharField(max_length=128, required=False, default="")
    metadata = serializers.JSONField(required=False, default=dict)
