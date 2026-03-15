from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="AgentDevice",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("agent_id", models.CharField(max_length=100, unique=True)),
                ("host_name", models.CharField(blank=True, default="", max_length=200)),
                ("host_ip", models.CharField(blank=True, default="", max_length=64)),
                ("agent_version", models.CharField(blank=True, default="", max_length=50)),
                ("status", models.CharField(default="unknown", max_length=20)),
                ("last_seen", models.DateTimeField(blank=True, null=True)),
                ("known_ips", models.JSONField(blank=True, default=list)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "Agente",
                "verbose_name_plural": "Agentes",
            },
        ),
        migrations.CreateModel(
            name="AgentCommand",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("command", models.CharField(choices=[("stop", "Stop"), ("restart", "Restart")], max_length=20)),
                ("status", models.CharField(choices=[("pending", "Pending"), ("issued", "Issued"), ("done", "Done"), ("failed", "Failed")], default="pending", max_length=20)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("executed_at", models.DateTimeField(blank=True, null=True)),
                ("message", models.TextField(blank=True, default="")),
                ("agent", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="commands", to="inventory.agentdevice")),
            ],
            options={
                "verbose_name": "Comando de Agente",
                "verbose_name_plural": "Comandos de Agente",
            },
        ),
        migrations.CreateModel(
            name="AgentInventorySnapshot",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("payload", models.JSONField(default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("agent", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="inventory_snapshots", to="inventory.agentdevice")),
            ],
            options={
                "verbose_name": "Inventario de Agente",
                "verbose_name_plural": "Inventarios de Agente",
            },
        ),
    ]
