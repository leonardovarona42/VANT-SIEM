from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("EVENT_M", "0001_initial"),
        ("inventory", "0004_aegisdlppolicy_agentdevice_last_dlp_at_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="aegisdlpincident",
            name="incidente",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="osic_threads", to="EVENT_M.incidente"),
        ),
        migrations.AddField(
            model_name="aegisdlpincident",
            name="reporte",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="osic_threads", to="EVENT_M.reporte"),
        ),
        migrations.AddField(
            model_name="aegisdlpincident",
            name="reported_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="aegisdlpincident",
            name="reported_by",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
    ]
