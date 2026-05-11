import json
import logging
import threading
from typing import Callable

import redis

logger = logging.getLogger('vant-siem.servicebus')


class ServiceBus:
    _instance = None
    _lock = threading.Lock()

    def __init__(self, url=None):
        self.redis = redis.from_url(url or 'redis://localhost:6379/10', decode_responses=True)
        self._listeners = {}
        self._running = False

    @classmethod
    def get_instance(cls, url=None):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(url)
        return cls._instance

    def publish(self, channel: str, event_type: str, payload: dict):
        message = json.dumps({
            'source': self._get_service_name(),
            'event': event_type,
            'payload': payload,
        })
        self.redis.publish(f"vant:{channel}", message)
        logger.debug("Published event: %s:%s", channel, event_type)

    def subscribe(self, channel: str, handler: Callable):
        if channel not in self._listeners:
            self._listeners[channel] = []
        self._listeners[channel].append(handler)

    def start_listening(self):
        if self._running:
            return
        self._running = True

        channels = [f"vant:{ch}" for ch in self._listeners.keys()]
        pubsub = self.redis.pubsub()
        pubsub.subscribe(*channels)

        thread = threading.Thread(target=self._listen_loop, args=(pubsub,), daemon=True)
        thread.start()
        logger.info("ServiceBus listening on: %s", channels)

    def _listen_loop(self, pubsub):
        while self._running:
            message = pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message and message['type'] == 'message':
                self._handle_message(message)

    def _handle_message(self, message):
        channel = message['channel'].replace("vant:", "")
        try:
            data = json.loads(message['data'])
            for handler in self._listeners.get(channel, []):
                try:
                    handler(data)
                except Exception as e:
                    logger.error("Handler error for %s: %s", channel, e)
        except json.JSONDecodeError:
            logger.error("Invalid message on %s: %s", channel, message['data'])

    def stop_listening(self):
        self._running = False

    @staticmethod
    def _get_service_name():
        import os
        return os.getenv('VANT_SERVICE_NAME', 'unknown')
