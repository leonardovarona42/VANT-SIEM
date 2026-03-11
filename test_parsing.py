#!/usr/bin/env python3
"""
Test script to verify parsing of IDS logs in both Windows and Debian environments
"""
import os
import sys
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

from opensearch_ui.parsers import (
    get_log_statistics, parse_suricata_line, parse_snort_line,
    parse_suricata_eve_json, parse_suricata_fast_log,
    parse_snort_alert_full, parse_snort_csv_line
)

def test_suricata_debian():
    """Test Suricata parsing on Debian logs"""
    print("=== Testing Suricata on Debian ===")

    log_dir = "ids-ips formatos/debian/suricata"

    # Test fast.log
    fast_path = os.path.join(log_dir, "fast.log")
    if os.path.exists(fast_path):
        print(f"Testing fast.log: {fast_path}")
        stats = get_log_statistics(fast_path, 'suricata')
        print(f"  Total lines: {stats['total_lines']}")
        print(f"  Parsed lines: {stats['parsed_lines']}")
        print(f"  Error lines: {stats['error_lines']}")
        print(f"  Severity counts: {stats['severity_counts']}")
        print(f"  Protocol counts: {stats['protocol_counts']}")
        if stats.get('error'):
            print(f"  Error: {stats['error']}")
        print()

    # Test eve.json (first 10 lines)
    eve_path = os.path.join(log_dir, "eve.json")
    if os.path.exists(eve_path):
        print(f"Testing eve.json: {eve_path}")
        parsed_count = 0
        error_count = 0
        with open(eve_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if i >= 10:  # Test only first 10 lines
                    break
                if line.strip():
                    try:
                        parsed = parse_suricata_eve_json(line)
                        if parsed:
                            parsed_count += 1
                            print(f"  Line {i+1}: OK - {parsed.get('event_type', 'unknown')}")
                        else:
                            error_count += 1
                            print(f"  Line {i+1}: Failed to parse")
                    except Exception as e:
                        error_count += 1
                        print(f"  Line {i+1}: Error - {e}")
        print(f"  Parsed: {parsed_count}, Errors: {error_count}")
        print()

def test_snort_debian():
    """Test Snort parsing on Debian logs (Snort 3)"""
    print("=== Testing Snort 3 on Debian ===")

    log_dir = "ids-ips formatos/debian/snort"

    # Test alert_fast.txt
    fast_path = os.path.join(log_dir, "alert_fast.txt")
    if os.path.exists(fast_path):
        print(f"Testing alert_fast.txt: {fast_path}")

        # Test individual lines
        with open(fast_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if i >= 5:  # Test first 5 lines
                    break
                line = line.strip()
                if line:
                    print(f"  Line {i+1}: {line[:100]}...")
                    try:
                        from opensearch_ui.parsers import SNORT_PATTERNS
                        parsed = None
                        for i, pattern in enumerate(SNORT_PATTERNS):
                            match = pattern.match(line)
                            if match:
                                print(f"    Matched pattern {i}")
                                try:
                                    from opensearch_ui.parsers import parse_timestamp
                                    timestamp = parse_timestamp(match.group('timestamp'), 'snort')
                                    if timestamp:
                                        print(f"    Timestamp OK")
                                        parsed = {'message': match.group('message')}
                                        break
                                    else:
                                        print(f"    Timestamp failed")
                                except Exception as e:
                                    print(f"    Timestamp error: {e}")
                                break
                        if parsed:
                            print(f"    OK - {parsed.get('message', '')[:50]}...")
                        else:
                            print(f"    Failed to parse")
                    except Exception as e:
                        print(f"    Error - {e}")

        # Test statistics (may fail due to Django settings)
        try:
            stats = get_log_statistics(fast_path, 'snort')
            print(f"  Total lines: {stats['total_lines']}")
            print(f"  Parsed lines: {stats['parsed_lines']}")
            print(f"  Error lines: {stats['error_lines']}")
            if stats.get('error'):
                print(f"  Error: {stats['error']}")
        except Exception as e:
            print(f"  Stats error: {e}")
        print()

def test_snort_windows():
    """Test Snort parsing on Windows logs"""
    print("=== Testing Snort on Windows ===")

    log_dir = "ids-ips formatos/windows/snort-log"

    # Test alerts.fast
    fast_path = os.path.join(log_dir, "alerts.fast")
    if os.path.exists(fast_path):
        print(f"Testing alerts.fast: {fast_path}")
        stats = get_log_statistics(fast_path, 'snort')
        print(f"  Total lines: {stats['total_lines']}")
        print(f"  Parsed lines: {stats['parsed_lines']}")
        print(f"  Error lines: {stats['error_lines']}")
        print(f"  Severity counts: {stats['severity_counts']}")
        print(f"  Protocol counts: {stats['protocol_counts']}")
        if stats.get('error'):
            print(f"  Error: {stats['error']}")
        print()

    # Test alerts.csv
    csv_path = os.path.join(log_dir, "alerts.csv")
    if os.path.exists(csv_path):
        print(f"Testing alerts.csv: {csv_path}")
        parsed_count = 0
        error_count = 0
        with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if i >= 10:  # Test only first 10 lines
                    break
                if line.strip():
                    try:
                        parsed = parse_snort_csv_line(line)
                        if parsed:
                            parsed_count += 1
                            print(f"  Line {i+1}: OK")
                        else:
                            error_count += 1
                            print(f"  Line {i+1}: Failed to parse")
                    except Exception as e:
                        error_count += 1
                        print(f"  Line {i+1}: Error - {e}")
        print(f"  Parsed: {parsed_count}, Errors: {error_count}")
        print()

if __name__ == "__main__":
    print("Testing IDS log parsing across environments\n")

    test_suricata_debian()
    test_snort_debian()
    test_snort_windows()

    print("Testing completed!")
