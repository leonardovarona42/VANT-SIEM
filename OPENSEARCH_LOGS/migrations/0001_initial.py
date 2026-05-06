from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='LogRetentionPolicy',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('source_type', models.CharField(choices=[('firewall_huawei', 'Huawei Firewall (USG/eudemon)'), ('snort', 'Snort IDS'), ('suricata', 'Suricata IDS'), ('windows_ad', 'Windows Active Directory'), ('windows_dhcp', 'Windows DHCP'), ('windows_dns', 'Windows DNS'), ('samba', 'Samba / Linux File Server'), ('switch', 'Network Switch'), ('router', 'Router'), ('modem', 'Modem'), ('agent_filelog', 'Agent File Log (Linux/Windows)'), ('generic_syslog', 'Generic Syslog'), ('firewall_cisco', 'Cisco Firewall (ASA/Firepower)'), ('fortigate', 'Fortinet FortiGate'), ('paloalto', 'Palo Alto Networks')], max_length=64, unique=True)),
                ('retention_days', models.IntegerField(default=90)),
                ('auto_delete', models.BooleanField(default=True)),
                ('last_cleanup_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'db_table': 'logs_retention_policies',
            },
        ),
        migrations.CreateModel(
            name='LogSource',
            fields=[
                ('source_id', models.CharField(db_index=True, max_length=128, primary_key=True, serialize=False)),
                ('source_type', models.CharField(choices=[('firewall_huawei', 'Huawei Firewall (USG/eudemon)'), ('snort', 'Snort IDS'), ('suricata', 'Suricata IDS'), ('windows_ad', 'Windows Active Directory'), ('windows_dhcp', 'Windows DHCP'), ('windows_dns', 'Windows DNS'), ('samba', 'Samba / Linux File Server'), ('switch', 'Network Switch'), ('router', 'Router'), ('modem', 'Modem'), ('agent_filelog', 'Agent File Log (Linux/Windows)'), ('generic_syslog', 'Generic Syslog'), ('firewall_cisco', 'Cisco Firewall (ASA/Firepower)'), ('fortigate', 'Fortinet FortiGate'), ('paloalto', 'Palo Alto Networks')], max_length=64)),
                ('vendor', models.CharField(choices=[('Huawei', 'Huawei'), ('Cisco', 'Cisco'), ('Microsoft', 'Microsoft'), ('Linux', 'Linux'), ('Palo Alto', 'Palo Alto Networks'), ('Fortinet', 'Fortinet'), ('Check Point', 'Check Point'), ('SonicWall', 'SonicWall'), ('Juniper', 'Juniper'), ('OpenSource', 'Open Source'), ('Unknown', 'Unknown')], default='Unknown', max_length=64)),
                ('model', models.CharField(blank=True, default='', max_length=128)),
                ('host_name', models.CharField(blank=True, default='', max_length=255)),
                ('host_ip', models.GenericIPAddressField(blank=True, null=True)),
                ('protocol', models.CharField(choices=[('syslog', 'Syslog (UDP/TCP)'), ('http_post', 'HTTP POST (JSON)'), ('agent_push', 'Agent Push (HTTPS)'), ('snmp_trap', 'SNMP Trap'), ('file_poll', 'File Polling'), ('api_pull', 'API Pull')], default='syslog', max_length=32)),
                ('port', models.IntegerField(blank=True, null=True)),
                ('api_key', models.CharField(blank=True, default='', max_length=256)),
                ('enabled', models.BooleanField(default=True)),
                ('meta', models.JSONField(blank=True, default=dict)),
                ('registered_at', models.DateTimeField(auto_now_add=True)),
                ('last_seen_at', models.DateTimeField(blank=True, null=True)),
            ],
            options={
                'db_table': 'logs_sources',
            },
        ),
        migrations.CreateModel(
            name='LogEvent',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('source_type', models.CharField(choices=[('firewall_huawei', 'Huawei Firewall (USG/eudemon)'), ('snort', 'Snort IDS'), ('suricata', 'Suricata IDS'), ('windows_ad', 'Windows Active Directory'), ('windows_dhcp', 'Windows DHCP'), ('windows_dns', 'Windows DNS'), ('samba', 'Samba / Linux File Server'), ('switch', 'Network Switch'), ('router', 'Router'), ('modem', 'Modem'), ('agent_filelog', 'Agent File Log (Linux/Windows)'), ('generic_syslog', 'Generic Syslog'), ('firewall_cisco', 'Cisco Firewall (ASA/Firepower)'), ('fortigate', 'Fortinet FortiGate'), ('paloalto', 'Palo Alto Networks')], db_index=True, max_length=64)),
                ('host_name', models.CharField(blank=True, db_index=True, default='', max_length=255)),
                ('host_ip', models.GenericIPAddressField(blank=True, null=True)),
                ('event_time', models.DateTimeField(db_index=True)),
                ('severity', models.CharField(choices=[('critical', 'Critical'), ('high', 'High'), ('medium', 'Medium'), ('low', 'Low'), ('info', 'Info'), ('debug', 'Debug')], db_index=True, default='info', max_length=16)),
                ('event_category', models.CharField(db_index=True, default='unknown', max_length=128)),
                ('message', models.TextField(blank=True, default='')),
                ('raw_payload', models.JSONField(blank=True, default=dict)),
                ('parsed_fields', models.JSONField(blank=True, default=dict)),
                ('tags', models.JSONField(blank=True, default=list)),
                ('ingested_at', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('source', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='events', to='OPENSEARCH_LOGS.logsource')),
            ],
            options={
                'db_table': 'logs_events_raw',
                'indexes': [models.Index(fields=['event_time', 'source_type'], name='logs_events_event_t_2a1f0e_idx'), models.Index(fields=['event_time', 'severity'], name='logs_events_event_t_5c9a2f_idx'), models.Index(fields=['host_ip', 'event_time'], name='logs_events_host_ip_1a2b3c_idx'), models.Index(fields=['severity', 'event_category'], name='logs_events_severit_4d5e6f_idx'), models.Index(fields=['event_category', 'event_time'], name='logs_events_event_c_7g8h9i_idx')],
            },
        ),
    ]
