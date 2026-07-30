
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("soc_app", "0003_add_medida_involucrado"),
    ]

    operations = [
        migrations.CreateModel(
            name="RetentionPolicy",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("entity_type", models.CharField(choices=[("logs_events", "Eventos de Log"), ("dlp_threats", "Amenazas DLP"), ("suricata_alerts", "Alertas Suricata"), ("audit_logs", "Logs de Auditoria"), ("incidentes", "Incidentes"), ("backups", "Respaldos")], max_length=30, unique=True)),
                ("retention_days", models.PositiveIntegerField(default=90)),
                ("action", models.CharField(choices=[("delete", "Eliminar"), ("archive", "Archivar")], default="delete", max_length=10)),
                ("is_active", models.BooleanField(default=True)),
                ("description", models.TextField(blank=True, default="")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "db_table": "soc_retention_policies",
                "ordering": ["entity_type"],
            },
        ),
        migrations.CreateModel(
            name="BackupRecord",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("backup_type", models.CharField(choices=[("full", "Completo"), ("partial", "Parcial")], default="full", max_length=10)),
                ("status", models.CharField(choices=[("pending", "Pendiente"), ("running", "En ejecucion"), ("completed", "Completado"), ("failed", "Fallido")], default="pending", max_length=10)),
                ("file_path", models.TextField(blank=True, default="")),
                ("file_size", models.BigIntegerField(default=0)),
                ("database_name", models.CharField(default="vantsiem", max_length=100)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("error_message", models.TextField(blank=True, default="")),
                ("notes", models.TextField(blank=True, default="")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={
                "db_table": "soc_backup_records",
                "ordering": ["-created_at"],
            },
        ),
    ]
