import re

# The alerts.fast pattern without classification
pattern = re.compile(
    r'(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<message>.*?)\s+\[\*\*\]\s+\[Priority:\s+(?P<priority>\d+)\]\s+\{(?P<protocol>\w+)\}\s+(?P<src_ip>[\d\.]+):(?P<src_port>\d+)\s+->\s+(?P<dst_ip>[\d\.]+):(?P<dst_port>\d+)'
)

line = '08/31-11:22:37.456144 [**] [1:1000002:1] "Conexión SSH detectada" [**] [Priority: 0] {TCP} 172.23.48.1:38458 -> 172.23.56.229:22'

match = pattern.match(line)
if match:
    print("Match found:")
    for key, value in match.groupdict().items():
        print(f"  {key}: {value}")
else:
    print("No match")

# Test with the actual line from the file (with encoding issue)
line2 = '08/31-11:22:37.456144 [**] [1:1000002:1] "Conexin SSH detectada" [**] [Priority: 0] {TCP} 172.23.48.1:38458 -> 172.23.56.229:22'

match2 = pattern.match(line2)
if match2:
    print("Match found for line2:")
    for key, value in match2.groupdict().items():
        print(f"  {key}: {value}")
else:
    print("No match for line2")