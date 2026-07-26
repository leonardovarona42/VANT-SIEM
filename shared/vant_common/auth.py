"""
VANT-SIEM Shared Auth Utilities.
JWT validation for users, token validation for agents, inter-service auth.
"""
import hashlib
import hmac
import logging
import os
import secrets
import time
from functools import wraps

import jwt
import redis

logger = logging.getLogger("vant_common.auth")

JWT_SECRET = os.getenv("JWT_SECRET", "changeme-generate-256bit-key")
JWT_ACCESS_TTL = int(os.getenv("JWT_ACCESS_TTL", "1800"))
JWT_REFRESH_TTL = int(os.getenv("JWT_REFRESH_TTL", "604800"))
SERVICE_SECRET = os.getenv("SERVICE_SECRET", "changeme-service-secret")

redis_pool = redis.ConnectionPool.from_url(
    os.getenv("REDIS_URL", "redis://127.0.0.1:6379/1"),
    decode_responses=True,
)
_redis = redis.Redis(connection_pool=redis_pool)


def generate_agent_token():
    return secrets.token_hex(32)


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create_jwt(user_id, username, role, extra_claims=None):
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "type": "access",
        "iat": now,
        "exp": now + JWT_ACCESS_TTL,
        "jti": secrets.token_hex(16),
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def create_refresh_token(user_id, username):
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "username": username,
        "type": "refresh",
        "iat": now,
        "exp": now + JWT_REFRESH_TTL,
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def decode_jwt(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        jti = payload.get("jti")
        if jti and _redis.get(f"jwt_blacklist:{jti}"):
            return None
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def blacklist_token(jti, exp):
    ttl = max(exp - int(time.time()), 0)
    if ttl > 0:
        _redis.setex(f"jwt_blacklist:{jti}", ttl, "1")


def validate_agent_token(token):
    cached = _redis.get(f"agent_token:{token}")
    if cached:
        return cached
    return None


def cache_agent_token(token, agent_id, ttl=300):
    _redis.setex(f"agent_token:{token}", ttl, agent_id)


def verify_service_secret(request):
    secret = request.META.get("HTTP_X_SERVICE_SECRET", "")
    return hmac.compare_digest(secret, SERVICE_SECRET)


def extract_token(request):
    auth_header = request.META.get("HTTP_AUTHORIZATION", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


def get_client_ip(request):
    x_forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded:
        return x_forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")
