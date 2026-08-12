import logging

from django.http import JsonResponse
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response

from . import services
from .models import (
    CriticalPort,
    FeedbackLabel,
    NetworkFeature,
    Playbook,
    PlaybookRun,
    SoarConfig,
    SoarModel,
    SoarPrediction,
    ThreatPort,
    get_or_create_config,
)
from .serializers import (
    ActOnPredictionRequestSerializer,
    CriticalPortSerializer,
    FeedbackRequestSerializer,
    NetworkFeatureSerializer,
    PlaybookRunSerializer,
    PlaybookSerializer,
    RetrainRequestSerializer,
    SoarConfigSerializer,
    SoarModelSerializer,
    SoarPredictionDetailSerializer,
    SoarPredictionSerializer,
    ThreatPortSerializer,
)

logger = logging.getLogger(__name__)


@api_view(["GET"])
def health_check(request):
    ok = True
    try:
        get_or_create_config()
    except Exception as exc:
        ok = False
        logger.exception("health fail: %s", exc)
    return Response({
        "service": "vant-soar",
        "status": "ok" if ok else "error",
        "time": timezone.now().isoformat(),
    }, status=200 if ok else 500)


@api_view(["GET", "PATCH"])
def config_view(request):
    cfg = get_or_create_config()
    if request.method == "PATCH":
        ser = SoarConfigSerializer(cfg, data=request.data, partial=True)
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response(ser.data)
    return Response(SoarConfigSerializer(cfg).data)


@api_view(["GET", "POST"])
def threat_ports_view(request):
    if request.method == "POST":
        ser = ThreatPortSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response(ser.data, status=status.HTTP_201_CREATED)
    qs = ThreatPort.objects.all()
    if request.GET.get("active") == "true":
        qs = qs.filter(is_active=True)
    return Response(ThreatPortSerializer(qs, many=True).data)


@api_view(["GET", "POST"])
def critical_ports_view(request):
    if request.method == "POST":
        ser = CriticalPortSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response(ser.data, status=status.HTTP_201_CREATED)
    qs = CriticalPort.objects.all()
    if request.GET.get("active") == "true":
        qs = qs.filter(is_active=True)
    return Response(CriticalPortSerializer(qs, many=True).data)


@api_view(["GET"])
def predictions_view(request):
    qs = SoarPrediction.objects.all()
    risk = request.GET.get("risk")
    status_f = request.GET.get("status")
    ip = request.GET.get("ip")
    if risk:
        qs = qs.filter(risk_level=risk)
    if status_f:
        qs = qs.filter(status=status_f)
    if ip:
        qs = qs.filter(ip=ip)
    qs = qs[: int(request.GET.get("limit", 100))]
    return Response(SoarPredictionSerializer(qs, many=True).data)


@api_view(["GET"])
def prediction_detail(request, pk):
    try:
        pred = SoarPrediction.objects.get(pk=pk)
    except SoarPrediction.DoesNotExist:
        return Response({"error": "not found"}, status=404)
    return Response(SoarPredictionDetailSerializer(pred).data)


@api_view(["POST"])
def prediction_feedback(request, pk):
    try:
        pred = SoarPrediction.objects.get(pk=pk)
    except SoarPrediction.DoesNotExist:
        return Response({"error": "not found"}, status=404)
    ser = FeedbackRequestSerializer(data=request.data)
    ser.is_valid(raise_exception=True)
    fb = services.label_prediction(
        pred, ser.validated_data["label"],
        notes=ser.validated_data.get("notes", ""),
        created_by=ser.validated_data.get("created_by", ""),
    )
    return Response({"ok": True, "feedback_id": fb.id, "status": pred.status})


@api_view(["POST"])
def prediction_act(request, pk):
    """Fuerza una acción (bloquear/investigar/monitorear) sobre una predicción."""
    try:
        pred = SoarPrediction.objects.get(pk=pk)
    except SoarPrediction.DoesNotExist:
        return Response({"error": "not found"}, status=404)
    ser = ActOnPredictionRequestSerializer(data=request.data)
    ser.is_valid(raise_exception=True)
    action = ser.validated_data["action"]
    if action == "block":
        pred.bus_event_id = services.publish_bus_event("commands", "block_ip", {
            "ip": pred.ip, "prediction_id": pred.id, "reason": "accion manual SOAR",
        })
    pred.decision = action
    pred.save()
    return Response({"ok": True, "decision": action, "bus_event_id": pred.bus_event_id})


@api_view(["GET"])
def features_view(request):
    qs = NetworkFeature.objects.all()
    ip = request.GET.get("ip")
    risk = request.GET.get("risk")
    if ip:
        qs = qs.filter(ip=ip)
    if risk:
        qs = qs.filter(risk_level=risk)
    qs = qs[: int(request.GET.get("limit", 100))]
    return Response(NetworkFeatureSerializer(qs, many=True).data)


@api_view(["GET"])
def models_view(request):
    return Response(SoarModelSerializer(SoarModel.objects.all(), many=True).data)


@api_view(["GET", "POST"])
def playbooks_view(request):
    if request.method == "POST":
        ser = PlaybookSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response(ser.data, status=status.HTTP_201_CREATED)
    return Response(PlaybookSerializer(Playbook.objects.all(), many=True).data)


@api_view(["GET"])
def playbook_runs_view(request):
    return Response(PlaybookRunSerializer(PlaybookRun.objects.all()[:50], many=True).data)


@api_view(["GET", "POST"])
def stats_view(request):
    cfg = get_or_create_config()
    data = {
        "predictions_total": SoarPrediction.objects.count(),
        "predictions_today": SoarPrediction.objects.filter(
            created_at__date=timezone.localdate()
        ).count(),
        "by_risk": {
            r: SoarPrediction.objects.filter(risk_level=r).count()
            for r in ("low", "medium", "high", "critical")
        },
        "false_positives": SoarPrediction.objects.filter(status="false_positive").count(),
        "confirmed": SoarPrediction.objects.filter(status="confirmed").count(),
        "open": SoarPrediction.objects.filter(status__in=("new", "acknowledged")).count(),
        "config": SoarConfigSerializer(cfg).data,
    }
    return Response(data)


@api_view(["POST"])
def analyze_now_view(request):
    """Forzar análisis de los últimos N minutos (o usar eventos simulados)."""
    cfg = get_or_create_config()
    minutes = int(request.data.get("minutes", 5))
    simulate = bool(request.data.get("simulate", False))
    if simulate:
        events = services.simulate_traffic(duration_seconds=int(request.data.get("duration", 15)))
    else:
        from django.db import connections

        events = services.get_recent_raw_events(minutes=minutes)
    preds = services.analyze_and_act(events, cfg)
    return Response({
        "events_analyzed": len(events),
        "predictions_created": len(preds),
        "predictions": SoarPredictionSerializer(preds, many=True).data,
    })


@api_view(["POST"])
def retrain_view(request):
    ser = RetrainRequestSerializer(data=request.data)
    ser.is_valid(raise_exception=True)
    try:
        metrics, samples, features = services.train_sklearn_model(
            model_name=ser.validated_data["model_name"],
            samples_limit=ser.validated_data.get("samples", 0),
        )
        return Response({"ok": True, "metrics": metrics, "samples": samples})
    except ValueError as exc:
        return Response({"ok": False, "error": str(exc)}, status=400)
