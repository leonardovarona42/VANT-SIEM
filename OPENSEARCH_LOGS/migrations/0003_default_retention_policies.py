from django.db import migrations

DEFAULT_POLICIES = [
    ('firewall_huawei', 180, True),
    ('snort', 90, True),
    ('suricata', 90, True),
    ('windows_ad', 180, True),
    ('windows_dhcp', 60, True),
    ('windows_dns', 60, True),
    ('samba', 90, True),
    ('generic_syslog', 60, True),
    ('agent_filelog', 90, True),
    ('switch', 60, True),
    ('router', 60, True),
    ('modem', 30, True),
]


def create_default_policies(apps, schema_editor):
    LogRetentionPolicy = apps.get_model('OPENSEARCH_LOGS', 'LogRetentionPolicy')
    policies = [
        LogRetentionPolicy(source_type=t, retention_days=d, auto_delete=a)
        for t, d, a in DEFAULT_POLICIES
    ]
    LogRetentionPolicy.objects.bulk_create(policies, ignore_conflicts=True)


def remove_default_policies(apps, schema_editor):
    LogRetentionPolicy = apps.get_model('OPENSEARCH_LOGS', 'LogRetentionPolicy')
    LogRetentionPolicy.objects.filter(source_type__in=[p[0] for p in DEFAULT_POLICIES]).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('OPENSEARCH_LOGS', '0002_timescaledb_hypertable'),
    ]

    operations = [
        migrations.RunPython(create_default_policies, reverse_code=remove_default_policies),
    ]
