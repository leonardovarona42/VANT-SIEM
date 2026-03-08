#!/usr/bin/env python
import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CORE.settings')
django.setup()

from opensearch_ui.models import IDSIngestConfig

# Restore original paths
configs = IDSIngestConfig.objects.all()
for config in configs:
    if config.ids_type == 'suricata':
        config.log_path = 'C:\\suricata-log'
    elif config.ids_type == 'snort':
        config.log_path = 'C:\\Snort\\log'
    config.save()
    print(f"Updated {config.ids_type}: {config.log_path}")

print("Configurations restored to original paths")
