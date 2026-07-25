# Generated manually — add collect_processes command + ProcessSnapshot model

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('INVENTORY', '0003_alter_agentcommand_command_type_screencapture'),
    ]

    operations = [
        migrations.AlterField(
            model_name='agentcommand',
            name='command_type',
            field=models.CharField(choices=[('update_inventory', 'Update Inventory'), ('restart_agent', 'Restart Agent'), ('stop_agent', 'Stop Agent'), ('update_agent', 'Update Agent'), ('run_script', 'Run Script'), ('collect_logs', 'Collect Logs'), ('collect_processes', 'Collect Processes & Ports'), ('push_config', 'Push Configuration'), ('start_screen_share', 'Start Screen Sharing'), ('stop_screen_share', 'Stop Screen Sharing'), ('custom', 'Custom')], max_length=32),
        ),
        migrations.CreateModel(
            name='ProcessSnapshot',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('processes', models.JSONField(default=list)),
                ('connections', models.JSONField(default=list)),
                ('captured_at', models.DateTimeField(auto_now_add=True)),
                ('agent', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='process_snapshots', to='INVENTORY.agent')),
            ],
            options={
                'db_table': 'process_snapshots',
                'ordering': ['-captured_at'],
                'indexes': [models.Index(fields=['agent', '-captured_at'], name='proc_snap_agent_i_a198f6_idx')],
            },
        ),
    ]
