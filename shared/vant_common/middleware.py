"""
VANT-SIEM Shared Django Middleware.
Service-to-service auth, agent token validation, request logging.
"""
import json
import logging
import time

from django.http import JsonResponse

from vant_common.auth import decode_jwt, extract_token, verify_service_secret, validate_agent_token, cache_agent_token
from vant_common.http_client import auth_validate_agent_token, auth_validate_jwt

logger = logging.getLogger("vant_common.middleware")


class ServiceAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith("/api/"):
            if request.path in ("/api/health/", "/api/health"):
                return self.get_response(request)
            if verify_service_secret(request):
                request.auth_type = "service"
                return self.get_response(request)
            token = extract_token(request)
            if token:
                agent_id = validate_agent_token(token)
                if agent_id:
                    request.auth_type = "agent"
                    request.agent_id = agent_id
                    return self.get_response(request)
                try:
                    result = auth_validate_agent_token(token)
                    if result and result.get("valid"):
                        request.auth_type = "agent"
                        request.agent_id = result.get("agent_id", "")
                        cache_agent_token(token, request.agent_id)
                        return self.get_response(request)
                except Exception:
                    pass
                try:
                    result = auth_validate_jwt(token)
                    if result and result.get("valid"):
                        request.auth_type = "user"
                        request.user_claims = result
                        return self.get_response(request)
                except Exception:
                    pass
                return JsonResponse({"error": "unauthorized", "detail": "Invalid token"}, status=401)
        return self.get_response(request)


class RequestTimingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        start = time.monotonic()
        response = self.get_response(request)
        elapsed = time.monotonic() - start
        if elapsed > 1.0:
            logger.warning("slow_request method=%s path=%s elapsed=%.2fs", request.method, request.path, elapsed)
        response["X-Response-Time"] = f"{elapsed:.3f}s"
        return response
