from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("soc_app", "0002_add_zone_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="medida",
            name="tipo",
            field=models.CharField(
                max_length=20,
                choices=[
                    ("preventiva", "Preventiva"),
                    ("reactiva", "Reactiva"),
                    ("recuperacion", "Recuperación"),
                ],
                default="preventiva",
                db_index=True,
            ),
        ),
    ]
