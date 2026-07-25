from rest_framework import serializers
from .models import LogSource, LogEvent, LogRetentionPolicy


class LogSourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = LogSource
        fields = '__all__'
        read_only_fields = ('registered_at', 'last_seen_at')


class LogEventListSerializer(serializers.ModelSerializer):
    source_name = serializers.CharField(source='source.source_id', read_only=True)

    class Meta:
        model = LogEvent
        fields = (
            'id', 'source_name', 'source_type', 'host_name', 'host_ip',
            'event_time', 'severity', 'event_category', 'message', 'tags', 'ingested_at',
            'parsed_fields',
        )


class LogEventDetailSerializer(serializers.ModelSerializer):
    source_name = serializers.CharField(source='source.source_id', read_only=True)

    class Meta:
        model = LogEvent
        fields = '__all__'


class LogIngestSerializer(serializers.Serializer):
    source_id = serializers.CharField(max_length=128)
    raw_message = serializers.CharField()
    source_type = serializers.CharField(max_length=64, required=False)
    event_time = serializers.DateTimeField(required=False)
    metadata = serializers.JSONField(required=False, default=dict)


class LogBulkIngestSerializer(serializers.Serializer):
    source_id = serializers.CharField(max_length=128)
    logs = serializers.ListField(child=serializers.DictField())

    def validate_logs(self, value):
        if len(value) > 5000:
            raise serializers.ValidationError('Max 5000 logs per bulk request')
        return value


class LogRetentionPolicySerializer(serializers.ModelSerializer):
    class Meta:
        model = LogRetentionPolicy
        fields = '__all__'
