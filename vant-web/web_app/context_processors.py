from django.conf import settings


def service_status(request):
    from . import http_client

    ctx = {}
    try:
        ctx["inventory_service_healthy"] = http_client.inventory_health()
    except Exception:
        ctx["inventory_service_healthy"] = False
    try:
        ctx["logs_service_healthy"] = http_client.logs_health()
    except Exception:
        ctx["logs_service_healthy"] = False
    try:
        ctx["soc_service_healthy"] = http_client.soc_health()
    except Exception:
        ctx["soc_service_healthy"] = False
    return ctx


def user_context(request):
    ctx = {
        "is_authenticated": request.session.get("jwt_token") is not None,
        "username": request.session.get("username", ""),
        "is_superuser": request.session.get("is_superuser", False),
    }
    if not ctx["is_authenticated"] and hasattr(request, "user") and request.user.is_authenticated:
        ctx["is_authenticated"] = True
        ctx["username"] = request.user.username
        ctx["is_superuser"] = request.user.is_superuser
    return ctx
