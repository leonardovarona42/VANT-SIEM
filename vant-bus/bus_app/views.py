"""
VANT-SIEM Bus API Views.
"""
import logging

from django.http import JsonResponse
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response

from bus_app.alert_dispatch import dispatch_alert
from bus_app.event_bus import STREAMS, get_event_bus
from bus_app.models import AlertChannel, AlertHistory
from bus_app.serializers import (
    AlertChannelSerializer,
    AlertHistorySerializer,
    SendAlertSerializer,
)
from vant_common.auth import verify_service_secret

logger = logging.getLogger("bus_app.views")


def _require_service_auth(request):
    if not verify_service_secret(request):
        return False
    return True


@api_view(["POST"])
def send_alert(request):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

    serializer = SendAlertSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    data = serializer.validated_data
    severity = data["severity"]
    title = data["title"]
    message = data["message"]
    source = data.get("source", "")
    metadata = data.get("metadata", {})

    bus = get_event_bus()
    bus.publish_alert(severity, title, message, source, metadata)

    dispatched = dispatch_alert(severity, title, message, source, metadata)

    return Response(
        {
            "status": "ok",
            "severity": severity,
            "dispatched_to": dispatched,
        },
        status=status.HTTP_200_OK,
    )


@api_view(["GET"])
def alert_history(request):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

    limit = min(int(request.query_params.get("limit", 50)), 500)
    severity = request.query_params.get("severity")
    channel = request.query_params.get("channel")

    qs = AlertHistory.objects.all()
    if severity:
        qs = qs.filter(severity=severity)
    if channel:
        qs = qs.filter(channel=channel)

    records = qs[:limit]
    serializer = AlertHistorySerializer(records, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(["GET", "POST"])
def alert_config(request):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

    if request.method == "GET":
        channels = AlertChannel.objects.all()
        serializer = AlertChannelSerializer(channels, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    channel_id = request.data.get("id")
    if channel_id:
        try:
            channel = AlertChannel.objects.get(id=channel_id)
        except AlertChannel.DoesNotExist:
            return Response(
                {"error": "channel not found"}, status=status.HTTP_404_NOT_FOUND
            )
        serializer = AlertChannelSerializer(channel, data=request.data, partial=True)
    else:
        serializer = AlertChannelSerializer(data=request.data)

    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    serializer.save()
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(["GET"])
def recent_events(request):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

    count = min(int(request.query_params.get("count", 50)), 500)
    stream_key = request.query_params.get("stream", "events")

    bus = get_event_bus()
    events = bus.get_recent_events(stream_key, count=count)
    return Response({"stream": stream_key, "events": events, "count": len(events)})


@api_view(["GET"])
def stream_events(request, stream):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

    if stream not in STREAMS:
        return Response(
            {"error": f"unknown stream: {stream}", "available": list(STREAMS.keys())},
            status=status.HTTP_400_BAD_REQUEST,
        )

    count = min(int(request.query_params.get("count", 100)), 1000)
    bus = get_event_bus()
    events = bus.get_recent_events(stream, count=count)
    return Response(
        {"stream": stream, "stream_name": STREAMS[stream], "events": events, "count": len(events)}
    )


@api_view(["GET"])
def stats(request):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

    bus = get_event_bus()
    stream_counts = bus.get_all_stream_counts()
    alert_count = AlertHistory.objects.count()
    channel_count = AlertChannel.objects.filter(is_active=True).count()

    return Response(
        {
            "streams": stream_counts,
            "total_events": sum(stream_counts.values()),
            "total_alerts": alert_count,
            "active_channels": channel_count,
        }
    )


@api_view(["GET"])
def health(request):
    bus = get_event_bus()
    bus_health = bus.health_check()
    return Response({"status": "ok", "service": "vant-bus", **bus_health})
