#!/usr/bin/env python3
"""
Test específico para verificar parsing de alert.full de Snort 3 en Debian
"""
import os
import sys
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

def test_alert_full_parsing():
    """Test parsing of Snort 3 alert.full format"""
    print("=== Testing Snort 3 alert.full Parsing ===\n")

    # Test multi-line alert block
    alert_block = """[**] [1:1000002:1] "Conexión SSH detectada" [**]
[Priority: 0]
08/31-11:22:37.456144 172.23.48.1:38458 -> 172.23.56.229:22
TCP TTL:48 TOS:0x0 ID:3052 IpLen:20 DgmLen:44
******S* Seq: 0xEC5273F6  Ack: 0x0  Win: 0x400  TcpLen: 24
TCP Options (1) => MSS: 1460"""

    print("Testing alert block parsing...")
    print("Block:")
    for i, line in enumerate(alert_block.split('\n'), 1):
        print(f"  {i}: {line}")
    print()

    # Mock Django settings to avoid configuration error
    import django
    from django.conf import settings
    if not settings.configured:
        settings.configure(
            USE_TZ=True,
            TIME_ZONE='UTC',
            SECRET_KEY='test-key'
        )
        django.setup()

    from opensearch_ui.parsers import parse_snort_alert_block

    lines = alert_block.split('\n')
    result = parse_snort_alert_block(lines)

    if result:
        print("[OK] Alert block parsed successfully:")
        print(f"  GID: {result.get('gid')}")
        print(f"  SID: {result.get('sid')}")
        print(f"  Message: {result.get('message')}")
        print(f"  Priority: {result.get('priority')}")
        print(f"  Protocol: {result.get('protocol')}")
        print(f"  Source: {result.get('src_ip')}:{result.get('src_port')}")
        print(f"  Dest: {result.get('dst_ip')}:{result.get('dst_port')}")
        print(f"  TTL: {result.get('ttl')}")
        print(f"  TCP Len: {result.get('tcp_len')}")
    else:
        print("[FAIL] Failed to parse alert block")

    print()

    # Test actual file parsing
    log_file = "ids-ips formatos/debian/snort/alert_full.txt"
    if os.path.exists(log_file):
        print(f"Testing actual file: {log_file}")
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Split into alert blocks (separated by blank lines)
            blocks = []
            current_block = []
            for line in content.split('\n'):
                line = line.strip()
                if line:
                    current_block.append(line)
                else:
                    if current_block:
                        blocks.append(current_block)
                        current_block = []
            if current_block:
                blocks.append(current_block)

            print(f"Found {len(blocks)} alert blocks in file")

            # Test parsing first few blocks
            parsed_count = 0
            for i, block in enumerate(blocks[:3]):  # Test first 3 blocks
                result = parse_snort_alert_block(block)
                if result:
                    parsed_count += 1
                    print(f"  Block {i+1}: [OK] - {result.get('message', '')[:30]}...")
                else:
                    print(f"  Block {i+1}: [FAIL]")

            print(f"  Result: {parsed_count}/{min(3, len(blocks))} blocks parsed successfully")

        except Exception as e:
            print(f"  Error reading file: {e}")
    else:
        print(f"  File not found: {log_file}")

if __name__ == "__main__":
    test_alert_full_parsing()
