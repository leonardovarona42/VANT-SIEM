
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("soc_app", "0001_add_tipo_to_medida"),
    ]

    operations = [
        migrations.AlterField(
            model_name="medidaincidente",
            name="responsable",
            field=models.ForeignKey(
                blank=True, null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                to="soc_app.Responsable",
            ),
        ),
        migrations.AlterField(
            model_name="medidaincidente",
            name="fecha_cumplimiento",
            field=models.DateField(blank=True, null=True),
        ),
        migrations.CreateModel(
            name="MedidaInvolucrado",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("fecha_cumplimiento", models.DateField(blank=True, null=True)),
                ("estado_cumplimiento", models.BooleanField(default=False)),
                ("observaciones", models.TextField(blank=True, default="")),
                ("involucrado", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="medidas", to="soc_app.Involucrado")),
                ("medida", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="soc_app.Medida")),
                ("responsable", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to="soc_app.Responsable")),
            ],
            options={
                "db_table": "soc_medidas_involucrado",
                "ordering": ["-fecha_cumplimiento"],
            },
        ),
    ]
