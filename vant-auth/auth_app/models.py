from django.db import models
from django.contrib.auth.hashers import make_password, check_password


class AuthUser(models.Model):
    ROLE_CHOICES = [("admin", "Admin"), ("analyst", "Analyst"), ("viewer", "Viewer")]
    id = models.BigAutoField(primary_key=True)
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    password_hash = models.CharField(max_length=256)
    first_name = models.CharField(max_length=150, blank=True, default="")
    last_name = models.CharField(max_length=150, blank=True, default="")
    phone = models.CharField(max_length=20, blank=True, default="")
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default="viewer")
    is_active = models.BooleanField(default=True)
    failed_login_attempts = models.IntegerField(default=0)
    last_login = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "auth_users"

    def set_password(self, raw):
        self.password_hash = make_password(raw)

    def check_password(self, raw):
        return check_password(raw, self.password_hash)


class AuthAgentToken(models.Model):
    id = models.BigAutoField(primary_key=True)
    agent_id = models.CharField(max_length=128, unique=True, db_index=True)
    hostname = models.CharField(max_length=255, blank=True, default="")
    token = models.CharField(max_length=256, unique=True, db_index=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "auth_agent_tokens"


class AuthAuditLog(models.Model):
    id = models.BigAutoField(primary_key=True)
    event = models.CharField(max_length=64)
    user_id = models.CharField(max_length=128, blank=True, default="")
    agent_id = models.CharField(max_length=128, blank=True, default="")
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    details = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "auth_audit_log"
        ordering = ["-created_at"]
