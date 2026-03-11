from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('ids_ingest', '0002_suricata_perf_indexes'),
    ]

    operations = [
        migrations.CreateModel(
            name='SavedDashboard',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('space', models.CharField(db_index=True, default='personal', max_length=64)),
                ('name', models.CharField(max_length=120)),
                ('description', models.TextField(blank=True, default='')),
                ('layout', models.JSONField(default=dict)),
                ('is_shared', models.BooleanField(db_index=True, default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='saved_dashboards', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-updated_at'],
            },
        ),
        migrations.CreateModel(
            name='SavedVisualization',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('space', models.CharField(db_index=True, default='personal', max_length=64)),
                ('name', models.CharField(max_length=120)),
                ('description', models.TextField(blank=True, default='')),
                ('config', models.JSONField(default=dict)),
                ('is_shared', models.BooleanField(db_index=True, default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='saved_visualizations', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-updated_at'],
            },
        ),
        migrations.AddIndex(
            model_name='saveddashboard',
            index=models.Index(fields=['owner', 'space', 'updated_at'], name='ids_ingest__owner_i_8e286c_idx'),
        ),
        migrations.AddIndex(
            model_name='saveddashboard',
            index=models.Index(fields=['space', 'is_shared', 'updated_at'], name='ids_ingest__space_i_c3a4c6_idx'),
        ),
        migrations.AddIndex(
            model_name='savedvisualization',
            index=models.Index(fields=['owner', 'space', 'updated_at'], name='ids_ingest__owner_i_09f502_idx'),
        ),
        migrations.AddIndex(
            model_name='savedvisualization',
            index=models.Index(fields=['space', 'is_shared', 'updated_at'], name='ids_ingest__space_i_5b44e3_idx'),
        ),
    ]
