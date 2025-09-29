#!/usr/bin/env python
import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CORE.settings')
django.setup()

from ids_ingest.parsers import parse_snort_line, parse_suricata_fast_log
from datetime import datetime
from django.utils import timezone

# Test Snort parsing
snort_line = "09/22-10:05:01.077361  [**] [129:5:1] Bad segment, adjusted size <= 0 [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 10.205.45.226:64105 -> 23.219.0.147:443"
print("Testing Snort line:")
print(f"Input: {snort_line}")
result = parse_snort_line(snort_line)
print(f"Result: {result}")
print()

# Test Suricata parsing
suricata_line = "09/22/2025-09:49:34.948852  [**] [1:2210054:1] SURICATA STREAM excessive retransmissions [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 10.205.45.226:63708 -> 216.150.1.193:443"
print("Testing Suricata line:")
print(f"Input: {suricata_line}")
result = parse_suricata_fast_log(suricata_line)
print(f"Result: {result}")
print()

# Test current time
print(f"Current time: {timezone.now()}")
print(f"Current year: {timezone.now().year}")