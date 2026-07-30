from rest_framework import serializers
from .models import LogSource, LogEventRaw, LogRetentionPolicy


class LogSourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = LogSource
        fields = '__all__'
        read_only_fields = ('registered_at', 'last_seen_at')


class LogEventListSerializer(serializers.ModelSerializer):
    source_name = serializers.CharField(source='source.source_id', read_only=True)

    class Meta:
        model = LogEventRaw
        fields = (
            'id', 'source_name', 'source_type', 'host_name', 'host_ip',
            'event_time', 'severity', 'event_category', 'message', 'tags', 'ingested_at',
            'parsed_fields', 'raw_payload',
        )


class LogEventDetailSerializer(serializers.ModelSerializer):
    source_name = serializers.CharField(source='source.source_id', read_only=True)

    class Meta:
        model = LogEventRaw
        fields = '__all__'


class LogBulkIngestSerializer(serializers.Serializer):
    events = serializers.ListField(child=serializers.DictField())

    def validate_events(self, value):
        if len(value) > 10000:
            raise serializers.ValidationError('Max 10000 events per bulk request')
        return value


class LogRetentionPolicySerializer(serializers.ModelSerializer):
    class Meta:
        model = LogRetentionPolicy
        fields = '__all__'
