#!/bin/bash
# VANT-SIEM Microservices — Run All Migrations
set -e

SERVICES_DIR="/opt/vant-siem/services"
VENV="/opt/vant-siem/venv"

echo "=== Running Migrations ==="

for svc in vant-auth vant-inventory vant-logs vant-aegis vant-intelligence vant-web; do
    echo "Migrating $svc..."
    cd "$SERVICES_DIR/$svc"
    "$VENV/bin/python" manage.py migrate --noinput 2>&1
    echo "  $svc migrated"
done

echo "=== Creating superuser (admin/admin) ==="
cd "$SERVICES_DIR/vant-auth"
"$VENV/bin/python" manage.py shell -c "
from auth_app.models import AuthUser
if not AuthUser.objects.filter(username='admin').exists():
    u = AuthUser(username='admin', email='admin@vantsiem.local', role='admin', first_name='Admin', last_name='System')
    u.set_password('admin')
    u.save()
    print('Superuser created: admin/admin')
else:
    print('Superuser already exists')
"

echo "=== All migrations complete ==="
