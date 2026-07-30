import json
import logging

import requests as http_requests
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

MAX_FAILED_ATTEMPTS = 5
BUS_SERVICE_URL = "http://127.0.0.1:8600/api"
SERVICE_SECRET = ""

import os
SERVICE_SECRET = os.getenv("SERVICE_SECRET", "changeme-service-secret")


def _publish_event(event_type, severity, payload):
    try:
        http_requests.post(
            f"{BUS_SERVICE_URL}/events/receive/",
            json={
                "event_type": event_type,
                "source_service": "auth",
                "entity_type": "usuario",
                "payload": payload,
                "severity": severity,
            },
            headers={"X-Service-Secret": SERVICE_SECRET},
            timeout=5,
        )
    except Exception as e:
        logger.warning("Failed to publish event to bus: %s", e)


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
        from vant_common.auth import verify_service_secret
        if verify_service_secret(request):
            request.jwt_claims = {"role": "admin", "sub": "service", "type": "access"}
            return view_func(self, request, *args, **kwargs)
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


def require_auth(view_func):
    def wrapper(self, request, *args, **kwargs):
        token = extract_token(request)
        if not token:
            return JsonResponse({"error": "unauthorized"}, status=401)
        claims = decode_jwt(token)
        if not claims or claims.get("type") != "access":
            return JsonResponse({"error": "unauthorized"}, status=401)
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
        ip = get_client_ip(request)

        try:
            user = AuthUser.objects.get(username=username)
        except AuthUser.DoesNotExist:
            _publish_event("login_fallido", "medium", {
                "username": username,
                "reason": "user_not_found",
                "ip": ip,
            })
            audit_log("login_failed", user_id=username, ip_address=ip, details={"reason": "user_not_found"})
            return json_error("Invalid credentials", 401)

        if not user.is_active:
            audit_log("login_failed", user_id=str(user.id), ip_address=ip, details={"reason": "inactive"})
            return json_error("Account is disabled. Contact an administrator.", 403)

        if not user.check_password(password):
            user.failed_login_attempts += 1
            user.save(update_fields=["failed_login_attempts"])

            audit_log("login_failed", user_id=str(user.id), ip_address=ip,
                      details={"reason": "bad_password", "attempts": user.failed_login_attempts})

            if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
                user.is_active = False
                user.save(update_fields=["is_active"])

                _publish_event("login_bloqueado", "critical", {
                    "user_id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "reason": "too_many_failed_attempts",
                    "attempts": user.failed_login_attempts,
                    "ip": ip,
                })

                audit_log("login_blocked", user_id=str(user.id), ip_address=ip,
                          details={"attempts": user.failed_login_attempts})
                return json_error("Account disabled due to too many failed attempts. Contact an administrator.", 403)

            remaining = MAX_FAILED_ATTEMPTS - user.failed_login_attempts
            return json_error(f"Invalid credentials. {remaining} attempts remaining.", 401)

        if user.failed_login_attempts > 0:
            user.failed_login_attempts = 0
            user.save(update_fields=["failed_login_attempts"])

        user.last_login = timezone.now()
        user.save(update_fields=["last_login"])

        access_token = create_jwt(user.id, user.username, user.role)
        refresh_token = create_refresh_token(user.id, user.username)

        _publish_event("login_exitoso", "info", {
            "user_id": user.id,
            "username": user.username,
            "ip": ip,
        })

        audit_log("login_success", user_id=str(user.id), ip_address=ip)
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
class AgentTokenCreateView(View):
    @require_service_secret
    def post(self, request):
        data = JSONParser().parse(request)
        agent_id = data.get("agent_id")
        hostname = data.get("hostname", "")
        token = data.get("token")
        if not agent_id or not token:
            return json_error("agent_id and token required")
        token_hash = hash_token(token)
        obj, created = AuthAgentToken.objects.update_or_create(
            agent_id=agent_id,
            defaults={"hostname": hostname, "token": token_hash, "is_active": True, "revoked_at": None},
        )
        cache_agent_token(token, agent_id)
        ip = get_client_ip(request)
        audit_log("agent_token_created", agent_id=agent_id, ip_address=ip)
        return JsonResponse({
            "agent_id": obj.agent_id,
            "hostname": obj.hostname,
            "detail": "Token registered successfully",
        }, status=201 if created else 200)


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
            phone=serializer.validated_data.get("phone", ""),
            role=serializer.validated_data.get("role", "viewer"),
        )
        user.set_password(serializer.validated_data["password"])
        user.save()

        _publish_event("usuario_creado", "info", {
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
        })

        ip = get_client_ip(request)
        audit_log("user_created", user_id=str(user.id), ip_address=ip, details={"username": user.username})
        return JsonResponse({"user": UserSerializer(user).data}, status=201)


@method_decorator(csrf_exempt, name="dispatch")
class UserUpdateView(View):
    @require_admin
    def get(self, request, user_id):
        try:
            user = AuthUser.objects.get(id=user_id)
        except AuthUser.DoesNotExist:
            return json_error("User not found", 404)
        return JsonResponse({"user": UserSerializer(user).data})

    @require_admin
    def put(self, request, user_id):
        try:
            user = AuthUser.objects.get(id=user_id)
        except AuthUser.DoesNotExist:
            return json_error("User not found", 404)

        data = JSONParser().parse(request)

        if "email" in data:
            user.email = data["email"]
        if "phone" in data:
            user.phone = data["phone"]
        if "first_name" in data:
            user.first_name = data["first_name"]
        if "last_name" in data:
            user.last_name = data["last_name"]
        if "role" in data:
            user.role = data["role"]
        if "is_active" in data:
            was_active = user.is_active
            user.is_active = data["is_active"]
            if was_active and not user.is_active:
                _publish_event("usuario_desabilitado", "medium", {
                    "user_id": user.id,
                    "username": user.username,
                    "reason": "admin_disabled",
                })

        if "password" in data and data["password"]:
            user.set_password(data["password"])
            user.failed_login_attempts = 0

        user.save()

        ip = get_client_ip(request)
        audit_log("user_updated", user_id=str(user.id), ip_address=ip, details={"fields": list(data.keys())})
        return JsonResponse({"user": UserSerializer(user).data})


@method_decorator(csrf_exempt, name="dispatch")
class UserResetPasswordView(View):
    @require_admin
    def post(self, request, user_id):
        try:
            user = AuthUser.objects.get(id=user_id)
        except AuthUser.DoesNotExist:
            return json_error("User not found", 404)

        data = JSONParser().parse(request)
        new_password = data.get("password")
        if not new_password:
            return json_error("password required")

        user.set_password(new_password)
        user.failed_login_attempts = 0
        user.save(update_fields=["password_hash", "failed_login_attempts"])

        ip = get_client_ip(request)
        audit_log("password_reset", user_id=str(user.id), ip_address=ip)
        return JsonResponse({"detail": f"Password reset for {user.username}"})


@method_decorator(csrf_exempt, name="dispatch")
class UserChangePasswordView(View):
    @require_auth
    def post(self, request):
        claims = request.jwt_claims
        try:
            user = AuthUser.objects.get(id=claims["sub"])
        except AuthUser.DoesNotExist:
            return json_error("User not found", 404)

        data = JSONParser().parse(request)
        old_password = data.get("old_password")
        new_password = data.get("new_password")

        if not old_password or not new_password:
            return json_error("old_password and new_password required")

        if not user.check_password(old_password):
            return json_error("Current password is incorrect", 401)

        user.set_password(new_password)
        user.save(update_fields=["password_hash"])

        audit_log("password_changed", user_id=str(user.id), ip_address=get_client_ip(request))
        return JsonResponse({"detail": "Password changed successfully"})


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
class UserMeView(View):
    def get(self, request):
        token = extract_token(request)
        if not token:
            return json_error("unauthorized", 401)
        claims = decode_jwt(token)
        if not claims or claims.get("type") != "access":
            return json_error("unauthorized", 401)
        try:
            user = AuthUser.objects.get(id=claims["sub"])
        except AuthUser.DoesNotExist:
            return json_error("User not found", 404)
        return JsonResponse({"user": UserSerializer(user).data})


@method_decorator(csrf_exempt, name="dispatch")
class HealthView(View):
    def get(self, request):
        return JsonResponse({"status": "healthy", "service": "vant-auth"})
