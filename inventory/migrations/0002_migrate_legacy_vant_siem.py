from django.db import migrations


def _table_exists(connection, table_name):
    return table_name in connection.introspection.table_names()


def migrate_legacy_inventory(apps, schema_editor):
    connection = schema_editor.connection
    legacy_device = "VANT_SIEM_agentdevice"
    legacy_command = "VANT_SIEM_agentcommand"
    legacy_snapshot = "VANT_SIEM_agentinventorysnapshot"

    new_device = "inventory_agentdevice"
    new_command = "inventory_agentcommand"
    new_snapshot = "inventory_agentinventorysnapshot"

    if not _table_exists(connection, legacy_device):
        return
    if not _table_exists(connection, new_device):
        return

    with connection.cursor() as cursor:
        cursor.execute(f"SELECT COUNT(1) FROM {new_device}")
        if cursor.fetchone()[0] > 0:
            return

        cursor.execute(
            f"""
            SELECT id, agent_id, host_name, host_ip, agent_version, status, last_seen, known_ips, created_at, updated_at
            FROM {legacy_device}
            """
        )
        device_rows = cursor.fetchall()
        if device_rows:
            cursor.executemany(
                f"""
                INSERT INTO {new_device}
                (id, agent_id, host_name, host_ip, agent_version, status, last_seen, known_ips, created_at, updated_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                device_rows,
            )

        if _table_exists(connection, legacy_command) and _table_exists(connection, new_command):
            cursor.execute(
                f"""
                SELECT id, command, status, created_at, executed_at, message, agent_id
                FROM {legacy_command}
                """
            )
            command_rows = cursor.fetchall()
            if command_rows:
                cursor.executemany(
                    f"""
                    INSERT INTO {new_command}
                    (id, command, status, created_at, executed_at, message, agent_id)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                    """,
                    command_rows,
                )

        if _table_exists(connection, legacy_snapshot) and _table_exists(connection, new_snapshot):
            cursor.execute(
                f"""
                SELECT id, payload, created_at, agent_id
                FROM {legacy_snapshot}
                """
            )
            snapshot_rows = cursor.fetchall()
            if snapshot_rows:
                cursor.executemany(
                    f"""
                    INSERT INTO {new_snapshot}
                    (id, payload, created_at, agent_id)
                    VALUES (%s,%s,%s,%s)
                    """,
                    snapshot_rows,
                )


class Migration(migrations.Migration):

    dependencies = [
        ("inventory", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(migrate_legacy_inventory, migrations.RunPython.noop),
    ]
