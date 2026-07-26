from rest_framework import serializers
from auth_app.models import AuthUser, AuthAgentToken


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(max_length=128, write_only=True)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuthUser
        fields = (
            "id", "username", "email", "first_name", "last_name",
            "role", "is_active", "last_login", "created_at", "updated_at",
        )
        read_only_fields = fields


class UserCreateSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    email = serializers.EmailField()
    password = serializers.CharField(max_length=128, write_only=True)
    first_name = serializers.CharField(max_length=150, required=False, default="")
    last_name = serializers.CharField(max_length=150, required=False, default="")
    role = serializers.ChoiceField(choices=AuthUser.ROLE_CHOICES, default="viewer")

    def validate_username(self, value):
        if AuthUser.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already exists.")
        return value

    def validate_email(self, value):
        if AuthUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists.")
        return value


class AgentRegisterSerializer(serializers.Serializer):
    agent_id = serializers.CharField(max_length=128)
    hostname = serializers.CharField(max_length=255, required=False, default="")


class AgentTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuthAgentToken
        fields = ("id", "agent_id", "hostname", "token", "is_active", "created_at", "last_used")
        read_only_fields = ("id", "token", "created_at", "last_used")


class TokenValidateSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=4096)
