from django.db import models


class UserPreference(models.Model):
    username = models.CharField(max_length=150, unique=True)
    theme = models.CharField(max_length=10, default="dark")
    language = models.CharField(max_length=10, default="es")
    items_per_page = models.PositiveIntegerField(default=25)
    dashboard_layout = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "user_preferences"

    def __str__(self):
        return f"{self.username} preferences"
