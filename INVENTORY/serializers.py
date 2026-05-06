from rest_framework import serializers
from .models import Agent, HardwareInventory, SoftwareInventory, AgentCommand


class AgentListSerializer(serializers.ModelSerializer):
    hardware_summary = serializers.SerializerMethodField()
    software_count = serializers.SerializerMethodField()

    class Meta:
        model = Agent
        fields = [
            'agent_id', 'hostname', 'machine_name', 'os_type', 'os_version',
            'agent_version', 'ip_address', 'mac_address', 'domain', 'status',
            'last_heartbeat', 'registered_at', 'updated_at', 'last_inventory_at',
            'tags', 'hardware_summary', 'software_count',
        ]

    def get_hardware_summary(self, obj):
        hw = getattr(obj, 'hardware', None)
        if not hw:
            return None
        return {
            'cpu': hw.cpu_model,
            'cores': hw.cpu_cores,
            'ram_gb': hw.ram_total_gb,
            'disk_total_gb': hw.disk_total_gb,
        }

    def get_software_count(self, obj):
        return obj.software.count()


class AgentDetailSerializer(serializers.ModelSerializer):
    hardware = serializers.SerializerMethodField()
    software = serializers.SerializerMethodField()
    pending_commands = serializers.SerializerMethodField()

    class Meta:
        model = Agent
        fields = '__all__'

    def get_hardware(self, obj):
        hw = getattr(obj, 'hardware', None)
        if not hw:
            return None
        return HardwareInventorySerializer(hw).data

    def get_software(self, obj):
        return SoftwareInventorySerializer(obj.software.all()[:50], many=True).data

    def get_pending_commands(self, obj):
        return obj.commands.filter(status='pending').count()


class AgentRegisterSerializer(serializers.Serializer):
    hostname = serializers.CharField(max_length=255)
    machine_name = serializers.CharField(max_length=255, required=False, allow_blank=True, default='')
    os_type = serializers.CharField(max_length=64)
    os_version = serializers.CharField(max_length=128, required=False, allow_blank=True, default='')
    os_arch = serializers.CharField(max_length=16, required=False, default='x86_64')
    agent_version = serializers.CharField(max_length=32, required=False, default='1.0.0')
    ip_address = serializers.IPAddressField(required=False, allow_null=True)
    mac_address = serializers.CharField(max_length=17, required=False, allow_blank=True, default='')
    domain = serializers.CharField(max_length=255, required=False, allow_blank=True, default='')
    tags = serializers.ListField(child=serializers.CharField(), required=False, default=list)


class HardwareInventorySerializer(serializers.ModelSerializer):
    class Meta:
        model = HardwareInventory
        fields = '__all__'


class SoftwareInventorySerializer(serializers.ModelSerializer):
    class Meta:
        model = SoftwareInventory
        fields = '__all__'


class SoftwareBulkSerializer(serializers.Serializer):
    software = SoftwareInventorySerializer(many=True)


class AgentCommandSerializer(serializers.ModelSerializer):
    class Meta:
        model = AgentCommand
        fields = '__all__'
        read_only_fields = ['command_id', 'created_at', 'sent_at', 'completed_at']


class AgentCommandCreateSerializer(serializers.Serializer):
    command_type = serializers.ChoiceField(choices=[c[0] for c in [('update_inventory', 'Update Inventory'), ('restart_agent', 'Restart Agent'), ('stop_agent', 'Stop Agent'), ('update_agent', 'Update Agent'), ('run_script', 'Run Script'), ('collect_logs', 'Collect Logs'), ('custom', 'Custom')]])
    payload = serializers.JSONField(required=False, default=dict)


class HeartbeatSerializer(serializers.Serializer):
    agent_id = serializers.UUIDField()
    ip_address = serializers.IPAddressField(required=False, allow_null=True)


class InventorySubmitSerializer(serializers.Serializer):
    agent_id = serializers.UUIDField()
    hardware = serializers.JSONField()
    software = serializers.JSONField(required=False, default=list)


class AgentStatsSerializer(serializers.Serializer):
    total_agents = serializers.IntegerField()
    online = serializers.IntegerField()
    offline = serializers.IntegerField()
    pending = serializers.IntegerField()
    error = serializers.IntegerField()
    disabled = serializers.IntegerField()
    os_distribution = serializers.JSONField()
    agents_by_day = serializers.JSONField()
