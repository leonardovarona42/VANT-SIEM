"""
VANT-SIEM Shared Bus Client.
Redis Pub/Sub + Streams for inter-service communication.
"""
import json
import logging
import os
import time
import traceback
from typing import Callable, Dict, List, Optional

import redis

logger = logging.getLogger("vant_common.bus")

REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/3")
STREAM_MAX_LEN = int(os.getenv("REDIS_STREAM_MAX_LEN", "100000"))

Streams = {
    "events": "vantsiem:events",
    "alerts": "vantsiem:alerts",
    "threats": "vantsiem:threats",
    "agents": "vantsiem:agents",
    "commands": "vantsiem:commands",
    "auth": "vantsiem:auth",
}


class EventBus:
    def __init__(self, service_name):
        self.service_name = service_name
        self._redis = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self._pubsub = self._redis.pubsub()
        self._subscribers: Dict[str, List[Callable]] = {}

    def publish_event(self, stream_key, event_type, data):
        payload = {
            "event_type": event_type,
            "service": self.service_name,
            "timestamp": str(time.time()),
            "data": json.dumps(data, default=str),
        }
        stream = Streams.get(stream_key, stream_key)
        msg_id = self._redis.xadd(stream, payload, maxlen=STREAM_MAX_LEN)
        channel = f"vantsiem:pubsub:{stream_key}"
        self._redis.publish(channel, json.dumps(payload))
        logger.debug("event published stream=%s type=%s id=%s", stream_key, event_type, msg_id)
        return msg_id

    def publish_alert(self, severity, title, message, source="", metadata=None):
        data = {
            "severity": severity,
            "title": title,
            "message": message,
            "source": source,
            "metadata": metadata or {},
        }
        return self.publish_event("alerts", "alert", data)

    def subscribe(self, stream_key, callback, group=None, consumer=None):
        stream = Streams.get(stream_key, stream_key)
        if group:
            try:
                self._redis.xgroup_create(stream, group, id="0", mkstream=True)
            except redis.exceptions.ResponseError:
                pass
            while True:
                try:
                    entries = self._redis.xreadgroup(
                        group, consumer or f"{self.service_name}-consumer",
                        {stream: ">"}, count=10, block=5000,
                    )
                    for _stream_name, messages in entries:
                        for msg_id, fields in messages:
                            try:
                                callback(fields)
                                self._redis.xack(stream, group, msg_id)
                            except Exception as e:
                                logger.error("callback error: %s", e)
                except (redis.exceptions.TimeoutError, redis.exceptions.ConnectionError):
                    continue  # timeout de block o conexión reestablecida: normal
                except Exception as e:
                    logger.error("subscribe error: %s | %s | %s", e, type(e).__module__, type(e).__name__)
                    traceback.print_exc()
                    time.sleep(1)
        else:
            self._pubsub.subscribe(**{
                f"vantsiem:pubsub:{stream_key}": lambda message: (
                    callback(json.loads(message["data"])) if message.get("data") else None
                )
            })
            for message in self._pubsub.listen():
                if message["type"] == "message":
                    try:
                        callback(json.loads(message["data"]))
                    except Exception as e:
                        logger.error("pubsub callback error: %s", e)

    def get_recent_events(self, stream_key, count=100):
        stream = Streams.get(stream_key, stream_key)
        entries = self._redis.xrevrange(stream, count=count)
        results = []
        for msg_id, fields in entries:
            entry = {"id": msg_id}
            entry.update(fields)
            if "data" in entry:
                try:
                    entry["data"] = json.loads(entry["data"])
                except (json.JSONDecodeError, TypeError):
                    pass
            results.append(entry)
        return results
