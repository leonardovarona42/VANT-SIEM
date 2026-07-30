from rest_framework import serializers

from bus_app.models import (
    AlertChannel,
    AlertHistory,
    EmailConfig,
    GroupAlertSubscription,
    GroupMember,
    NotificationGroup,
    NotificationLog,
    ServiceConfig,
    ServiceHealthLog,
    SystemEvent,
)


class SystemEventSerializer(serializers.ModelSerializer):
    event_type_display = serializers.CharField(source="get_event_type_display", read_only=True)
    severity_display = serializers.CharField(source="get_severity_display", read_only=True)

    class Meta:
        model = SystemEvent
        fields = [
            "id", "event_type", "event_type_display", "source_service",
            "entity_type", "entity_id", "actor_user_id", "actor_username",
            "payload", "severity", "severity_display", "created_at", "processed",
        ]
        read_only_fields = ["id", "created_at"]


class NotificationGroupSerializer(serializers.ModelSerializer):
    members_count = serializers.SerializerMethodField()

    class Meta:
        model = NotificationGroup
        fields = ["id", "name", "description", "is_active", "created_at", "members_count"]
        read_only_fields = ["id", "created_at"]

    def get_members_count(self, obj):
        return obj.members.count()


class GroupMemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = GroupMember
        fields = ["id", "group", "user_id", "username", "email", "added_at"]
        read_only_fields = ["id", "added_at"]


class GroupAlertSubscriptionSerializer(serializers.ModelSerializer):
    event_type_display = serializers.SerializerMethodField()

    class Meta:
        model = GroupAlertSubscription
        fields = ["id", "group", "event_type", "event_type_display", "channel", "is_active", "created_at"]
        read_only_fields = ["id", "created_at"]

    def get_event_type_display(self, obj):
        return dict(SystemEvent.EVENT_TYPE_CHOICES).get(obj.event_type, obj.event_type)


class EmailConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmailConfig
        fields = [
            "id", "smtp_host", "smtp_port", "smtp_user", "smtp_password",
            "use_tls", "from_address", "is_active", "updated_at",
        ]
        read_only_fields = ["id", "updated_at"]
        extra_kwargs = {
            "smtp_password": {"write_only": True},
        }


class NotificationLogSerializer(serializers.ModelSerializer):
    event_type = serializers.CharField(source="event.event_type", read_only=True)
    event_payload = serializers.JSONField(source="event.payload", read_only=True)
    group_name = serializers.CharField(source="group.name", read_only=True)

    class Meta:
        model = NotificationLog
        fields = [
            "id", "event", "event_type", "event_payload", "group", "group_name",
            "channel", "recipient_user_id", "recipient_email", "status",
            "sent_at", "read_at", "error_message", "created_at",
        ]
        read_only_fields = ["id", "created_at"]


class ServiceConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = ServiceConfig
        fields = [
            "id", "name", "display_name", "host", "port", "health_endpoint",
            "systemd_service", "is_critical", "is_active",
            "last_health_check", "last_health_status", "consecutive_failures",
            "created_at",
        ]
        read_only_fields = ["id", "created_at", "last_health_check", "last_health_status", "consecutive_failures"]


class ServiceHealthLogSerializer(serializers.ModelSerializer):
    service_name = serializers.CharField(source="service.name", read_only=True)

    class Meta:
        model = ServiceHealthLog
        fields = ["id", "service", "service_name", "status", "response_time_ms", "details", "checked_at"]
        read_only_fields = ["id", "checked_at"]


class AlertChannelSerializer(serializers.ModelSerializer):
    class Meta:
        model = AlertChannel
        fields = ["id", "name", "channel_type", "config", "is_active", "severity_filter", "created_at"]
        read_only_fields = ["id", "created_at"]


class AlertHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = AlertHistory
        fields = ["id", "severity", "title", "message", "source", "channel", "status", "metadata", "sent_at"]
        read_only_fields = ["id", "sent_at"]


class CreateEventSerializer(serializers.Serializer):
    event_type = serializers.ChoiceField(choices=SystemEvent.EVENT_TYPE_CHOICES)
    source_service = serializers.CharField(max_length=32)
    entity_type = serializers.CharField(max_length=32, required=False, default="", allow_blank=True)
    entity_id = serializers.CharField(max_length=64, required=False, default="", allow_blank=True)
    actor_user_id = serializers.CharField(max_length=64, required=False, default="", allow_blank=True)
    actor_username = serializers.CharField(max_length=150, required=False, default="", allow_blank=True)
    payload = serializers.JSONField(required=False, default=dict)
    severity = serializers.ChoiceField(choices=SystemEvent.SEVERITY_CHOICES, default="info")
