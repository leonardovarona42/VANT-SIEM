from django.core.management.base import BaseCommand

from soar_app import services


class Command(BaseCommand):
    help = "Entrena el modelo sklearn (incident_risk) con las muestras etiquetadas"

    def add_arguments(self, parser):
        parser.add_argument("--samples", type=int, default=0, help="0 = todos")
        parser.add_argument("--model-name", default="incident_risk")
        parser.add_argument("--rf", action="store_true", help="Usar RandomForest en vez de GradientBoosting")

    def handle(self, *args, **opts):
        try:
            metrics, samples, features = services.train_sklearn_model(
                model_name=opts["model_name"],
                samples_limit=opts["samples"],
                xgb=not opts["rf"],
            )
        except ValueError as exc:
            self.stderr.write(self.style.ERROR(str(exc)))
            return
        self.stdout.write(self.style.SUCCESS(f"Entrenado con {samples} muestras: {metrics}"))
        self.stdout.write(f"Features ({len(features)}): {', '.join(features)}")
