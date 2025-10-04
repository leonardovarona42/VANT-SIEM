#!/usr/bin/env python3
"""
Test específico para verificar parsing de logs de Snort 3 en Debian
"""
import os
import sys
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

def test_snort_debian_parsing():
    """Test parsing of Snort 3 logs from Debian"""
    print("=== Testing Snort 3 Debian Log Parsing ===\n")

    # Test lines from the actual log file
    test_lines = [
        '08/31-11:22:37.456144 [**] [1:1000002:1] "Conexión SSH detectada" [**] [Priority: 0] {TCP} 172.23.48.1:38458 -> 172.23.56.229:22',
        '08/31-11:22:37.472334 [**] [1:1418:19] "PROTOCOL-SNMP request tcp" [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 172.23.48.1:38458 -> 172.23.56.229:161',
        '08/31-11:22:39.380969 [**] [1:1000001:1] "Ping detectado" [**] [Priority: 0] {ICMP} 172.23.48.1 -> 172.23.56.229',
        '08/31-11:22:39.380969 [**] [1:382:11] "PROTOCOL-ICMP PING Windows" [**] [Classification: Misc activity] [Priority: 3] {ICMP} 172.23.48.1 -> 172.23.56.229'
    ]

    from ids_ingest.parsers import SNORT_PATTERNS

    for i, line in enumerate(test_lines, 1):
        print(f"Test Line {i}: {line[:80]}...")
        parsed = False
        for j, pattern in enumerate(SNORT_PATTERNS):
            match = pattern.match(line)
            if match:
                print(f"  [OK] Matched Pattern {j}")
                groups = match.groupdict()
                print(f"    GID: {groups.get('gid')}, SID: {groups.get('sid')}, Message: {groups.get('message')[:30]}...")
                print(f"    Protocol: {groups.get('protocol')}, Priority: {groups.get('priority')}")
                if 'classification' in groups and groups['classification']:
                    print(f"    Classification: {groups.get('classification')}")
                parsed = True
                break
        if not parsed:
            print("  [FAIL] No pattern matched")
        print()

    # Test actual file parsing
    log_file = "ids-ips formatos/debian/snort/alert_fast.txt"
    if os.path.exists(log_file):
        print(f"Testing actual file: {log_file}")
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines_tested = 0
                lines_parsed = 0
                for line_num, line in enumerate(f, 1):
                    if lines_tested >= 10:  # Test first 10 lines
                        break
                    line = line.strip()
                    if line:
                        lines_tested += 1
                        parsed = False
                        for pattern in SNORT_PATTERNS:
                            if pattern.match(line):
                                lines_parsed += 1
                                parsed = True
                                break
                        if not parsed:
                            print(f"  Line {line_num}: Failed to parse")
                print(f"  Result: {lines_parsed}/{lines_tested} lines parsed successfully")
        except Exception as e:
            print(f"  Error reading file: {e}")
    else:
        print(f"  File not found: {log_file}")

if __name__ == "__main__":
    test_snort_debian_parsing()