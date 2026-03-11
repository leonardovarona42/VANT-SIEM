import re

line = '09/19-00:27:15.026239 ,"Consecutive TCP small segments exceeding threshold",,,8443,6283,TCP,,'

pattern = re.compile(
    r'(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s*,\s*"(?P<message>.*?)",,,(?P<src_port>\d+),(?P<dst_port>\d+),(?P<protocol>\w+),,'
)

match = pattern.match(line)
if match:
    print("Match found:")
    print(f"timestamp: {match.group('timestamp')}")
    print(f"message: {match.group('message')}")
    print(f"src_port: {match.group('src_port')}")
    print(f"dst_port: {match.group('dst_port')}")
    print(f"protocol: {match.group('protocol')}")
else:
    print("No match")