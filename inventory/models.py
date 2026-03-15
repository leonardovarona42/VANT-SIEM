from django.db import models


class AgentDevice(models.Model):
    agent_id = models.CharField(max_length=100, unique=True)
    host_name = models.CharField(max_length=200, blank=True, default="")
    host_ip = models.CharField(max_length=64, blank=True, default="")
    agent_version = models.CharField(max_length=50, blank=True, default="")
    status = models.CharField(max_length=20, default="unknown")
    last_seen = models.DateTimeField(null=True, blank=True)
    known_ips = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Agente"
        verbose_name_plural = "Agentes"

    def __str__(self):
        return f"{self.agent_id} ({self.host_name})"


class AgentCommand(models.Model):
    COMMAND_CHOICES = [
        ("stop", "Stop"),
        ("restart", "Restart"),
    ]
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("issued", "Issued"),
        ("done", "Done"),
        ("failed", "Failed"),
    ]
    agent = models.ForeignKey(AgentDevice, on_delete=models.CASCADE, related_name="commands")
    command = models.CharField(max_length=20, choices=COMMAND_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    created_at = models.DateTimeField(auto_now_add=True)
    executed_at = models.DateTimeField(null=True, blank=True)
    message = models.TextField(blank=True, default="")

    class Meta:
        verbose_name = "Comando de Agente"
        verbose_name_plural = "Comandos de Agente"

    def __str__(self):
        return f"{self.agent.agent_id} {self.command} ({self.status})"


class AgentInventorySnapshot(models.Model):
    agent = models.ForeignKey(AgentDevice, on_delete=models.CASCADE, related_name="inventory_snapshots")
    payload = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Inventario de Agente"
        verbose_name_plural = "Inventarios de Agente"

    def __str__(self):
        return f"{self.agent.agent_id} {self.created_at}"
