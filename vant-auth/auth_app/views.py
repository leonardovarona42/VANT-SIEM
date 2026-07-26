import logging

from django.http import JsonResponse
from django.urls import path
from django.utils import timezone
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from rest_framework.parsers import JSONParser

from auth_app.models import AuthUser, AuthAgentToken, AuthAuditLog
from auth_app.serializers import (
    LoginSerializer,
    UserSerializer,
    UserCreateSerializer,
    AgentRegisterSerializer,
    AgentTokenSerializer,
)
from vant_common.auth import (
    create_jwt,
    create_refresh_token,
    decode_jwt,
    blacklist_token,
    generate_agent_token,
    hash_token,
    verify_service_secret,
    extract_token,
    get_client_ip,
    cache_agent_token,
    validate_agent_token,
)

logger = logging.getLogger("vant_auth.views")


def audit_log(event, user_id="", agent_id="", ip_address=None, details=None):
    try:
        AuthAuditLog.objects.create(
            event=event,
            user_id=str(user_id),
            agent_id=str(agent_id),
            ip_address=ip_address,
            details=details or {},
        )
    except Exception:
        logger.exception("Failed to write audit log event=%s", event)


def json_error(message, status=400):
    return JsonResponse({"error": message}, status=status)


def require_service_secret(view_func):
    def wrapper(self, request, *args, **kwargs):
        if not verify_service_secret(request):
            return JsonResponse({"error": "forbidden", "detail": "Invalid service secret"}, status=403)
        return view_func(self, request, *args, **kwargs)
    return wrapper


def require_admin(view_func):
    def wrapper(self, request, *args, **kwargs):
        token = extract_token(request)
        if not token:
            return JsonResponse({"error": "unauthorized", "detail": "Missing token"}, status=401)
        claims = decode_jwt(token)
        if not claims:
            return JsonResponse({"error": "unauthorized", "detail": "Invalid token"}, status=401)
        if claims.get("type") != "access":
            return JsonResponse({"error": "unauthorized", "detail": "Not an access token"}, status=401)
        if claims.get("role") != "admin":
            return JsonResponse({"error": "forbidden", "detail": "Admin role required"}, status=403)
        request.jwt_claims = claims
        return view_func(self, request, *args, **kwargs)
    return wrapper


@method_decorator(csrf_exempt, name="dispatch")
class LoginView(View):
    def post(self, request):
        data = JSONParser().parse(request)
        serializer = LoginSerializer(data=data)
        if not serializer.is_valid():
            return json_error(serializer.errors)

        username = serializer.validated_data["username"]
        password = serializer.validated_data["password"]

        try:
            user = AuthUser.objects.get(username=username)
        except AuthUser.DoesNotExist:
            audit_log("login_failed", user_id=username, ip_address=get_client_ip(request), details={"reason": "user_not_found"})
            return json_error("Invalid credentials", 401)

        if not user.is_active:
            audit_log("login_failed", user_id=str(user.id), ip_address=get_client_ip(request), details={"reason": "inactive"})
            return json_error("Account is disabled", 403)

        if not user.check_password(password):
            audit_log("login_failed", user_id=str(user.id), ip_address=get_client_ip(request), details={"reason": "bad_password"})
            return json_error("Invalid credentials", 401)

        user.last_login = timezone.now()
        user.save(update_fields=["last_login"])

        access_token = create_jwt(user.id, user.username, user.role)
        refresh_token = create_refresh_token(user.id, user.username)

        audit_log("login_success", user_id=str(user.id), ip_address=get_client_ip(request))
        return JsonResponse({
            "access": access_token,
            "refresh": refresh_token,
            "user": UserSerializer(user).data,
        })


@method_decorator(csrf_exempt, name="dispatch")
class RefreshView(View):
    def post(self, request):
        data = JSONParser().parse(request)
        token = data.get("refresh")
        if not token:
            return json_error("Refresh token required")

        claims = decode_jwt(token)
        if not claims:
            return json_error("Invalid or expired refresh token", 401)
        if claims.get("type") != "refresh":
            return json_error("Token is not a refresh token", 401)

        new_access = create_jwt(claims["sub"], claims["username"], claims.get("role", "viewer"))
        return JsonResponse({"access": new_access})


@method_decorator(csrf_exempt, name="dispatch")
class LogoutView(View):
    def post(self, request):
        data = JSONParser().parse(request)
        token = data.get("token") or extract_token(request)
        if not token:
            return json_error("Token required")

        claims = decode_jwt(token)
        if not claims:
            return json_error("Invalid token", 401)

        jti = claims.get("jti")
        exp = claims.get("exp")
        if jti and exp:
            blacklist_token(jti, exp)

        ip = get_client_ip(request)
        audit_log("logout", user_id=claims.get("sub", ""), ip_address=ip)
        return JsonResponse({"detail": "Logged out"})


@method_decorator(csrf_exempt, name="dispatch")
class TokenValidateView(View):
    @require_service_secret
    def post(self, request):
        data = JSONParser().parse(request)
        token = data.get("token")
        if not token:
            return json_error("Token required")

        claims = decode_jwt(token)
        if claims:
            return JsonResponse({"valid": True, "claims": claims})

        if AuthAgentToken.objects.filter(token=hash_token(token), is_active=True).exists():
            agent_token = AuthAgentToken.objects.get(token=hash_token(token))
            agent_token.last_used = timezone.now()
            agent_token.save(update_fields=["last_used"])
            cache_agent_token(token, agent_token.agent_id)
            return JsonResponse({"valid": True, "agent_id": agent_token.agent_id})

        return JsonResponse({"valid": False}, status=401)


@method_decorator(csrf_exempt, name="dispatch")
class AgentRegisterView(View):
    def post(self, request):
        data = JSONParser().parse(request)
        serializer = AgentRegisterSerializer(data=data)
        if not serializer.is_valid():
            return json_error(serializer.errors)

        agent_id = serializer.validated_data["agent_id"]
        hostname = serializer.validated_data.get("hostname", "")

        raw_token = generate_agent_token()
        token_hash = hash_token(raw_token)

        obj, created = AuthAgentToken.objects.update_or_create(
            agent_id=agent_id,
            defaults={"hostname": hostname, "token": token_hash, "is_active": True, "revoked_at": None},
        )

        ip = get_client_ip(request)
        audit_log("agent_registered", agent_id=agent_id, ip_address=ip)
        return JsonResponse({
            "agent_id": obj.agent_id,
            "token": raw_token,
            "hostname": obj.hostname,
            "detail": "Store the token securely. It will not be shown again.",
        })


@method_decorator(csrf_exempt, name="dispatch")
class AgentValidateView(View):
    @require_service_secret
    def post(self, request):
        data = JSONParser().parse(request)
        token = data.get("token")
        if not token:
            return json_error("Token required")

        token_hash = hash_token(token)
        try:
            agent_token = AuthAgentToken.objects.get(token=token_hash, is_active=True)
        except AuthAgentToken.DoesNotExist:
            return JsonResponse({"valid": False}, status=401)

        agent_token.last_used = timezone.now()
        agent_token.save(update_fields=["last_used"])
        cache_agent_token(token, agent_token.agent_id)
        return JsonResponse({"valid": True, "agent_id": agent_token.agent_id})


@method_decorator(csrf_exempt, name="dispatch")
class AgentRevokeView(View):
    @require_admin
    def post(self, request):
        data = JSONParser().parse(request)
        agent_id = data.get("agent_id")
        token_id = data.get("token_id")

        if not agent_id and not token_id:
            return json_error("agent_id or token_id required")

        try:
            if token_id:
                agent_token = AuthAgentToken.objects.get(id=token_id)
            else:
                agent_token = AuthAgentToken.objects.get(agent_id=agent_id)
        except AuthAgentToken.DoesNotExist:
            return json_error("Agent token not found", 404)

        agent_token.is_active = False
        agent_token.revoked_at = timezone.now()
        agent_token.save(update_fields=["is_active", "revoked_at"])

        ip = get_client_ip(request)
        audit_log("agent_revoked", agent_id=agent_token.agent_id, ip_address=ip)
        return JsonResponse({"detail": f"Agent {agent_token.agent_id} revoked"})


@method_decorator(csrf_exempt, name="dispatch")
class UserListView(View):
    @require_admin
    def get(self, request):
        users = AuthUser.objects.all().order_by("-created_at")
        return JsonResponse({"users": UserSerializer(users, many=True).data})


@method_decorator(csrf_exempt, name="dispatch")
class UserCreateView(View):
    @require_admin
    def post(self, request):
        data = JSONParser().parse(request)
        serializer = UserCreateSerializer(data=data)
        if not serializer.is_valid():
            return json_error(serializer.errors)

        user = AuthUser(
            username=serializer.validated_data["username"],
            email=serializer.validated_data["email"],
            first_name=serializer.validated_data.get("first_name", ""),
            last_name=serializer.validated_data.get("last_name", ""),
            role=serializer.validated_data.get("role", "viewer"),
        )
        user.set_password(serializer.validated_data["password"])
        user.save()

        ip = get_client_ip(request)
        audit_log("user_created", user_id=str(user.id), ip_address=ip, details={"username": user.username})
        return JsonResponse({"user": UserSerializer(user).data}, status=201)


@method_decorator(csrf_exempt, name="dispatch")
class UserDeleteView(View):
    @require_admin
    def delete(self, request, user_id):
        try:
            user = AuthUser.objects.get(id=user_id)
        except AuthUser.DoesNotExist:
            return json_error("User not found", 404)

        ip = get_client_ip(request)
        username = user.username
        user.delete()
        audit_log("user_deleted", user_id=str(user_id), ip_address=ip, details={"username": username})
        return JsonResponse({"detail": f"User {username} deleted"})


@method_decorator(csrf_exempt, name="dispatch")
class HealthView(View):
    def get(self, request):
        return JsonResponse({"status": "healthy", "service": "vant-auth"})



