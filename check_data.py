from opensearch_ui.models import SuricataEveAlert
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count

now = timezone.now()
logs = SuricataEveAlert.objects.filter(event_type='alert', timestamp__gte=now-timedelta(hours=24))

print('Sample records:')
for log in logs[:5]:
    print(f'  src_ip={log.src_ip}, dest_ip={log.dest_ip}, proto={log.proto}')

print('\nTop src_ips:')
top_src = list(logs.values('src_ip').annotate(count=Count('id')).order_by('-count')[:5])
print(top_src)

print('\nTop dest_ips:')
top_dest = list(logs.values('dest_ip').annotate(count=Count('id')).order_by('-count')[:5])
print(top_dest)
