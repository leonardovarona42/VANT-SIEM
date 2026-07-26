"""
VANT-SIEM Alert Dispatch Engine.
Email, Telegram, and Webhook dispatch with retry logic.
"""
import hashlib
import hmac
import json
import logging
import os
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List

import requests

from bus_app.models import AlertChannel, AlertHistory

logger = logging.getLogger("bus_app.alert_dispatch")

ALERT_EMAIL_HOST = os.getenv("ALERT_EMAIL_HOST", "smtp.gmail.com")
ALERT_EMAIL_PORT = int(os.getenv("ALERT_EMAIL_PORT", "587"))
ALERT_EMAIL_USER = os.getenv("ALERT_EMAIL_USER", "")
ALERT_EMAIL_PASSWORD = os.getenv("ALERT_EMAIL_PASSWORD", "")
ALERT_EMAIL_FROM = os.getenv("ALERT_EMAIL_FROM", "vant-alerts@example.com")
ALERT_EMAIL_USE_TLS = (
    os.getenv("ALERT_EMAIL_USE_TLS", "True").lower() in ("true", "1", "yes")
)
ALERT_TELEGRAM_BOT_TOKEN = os.getenv("ALERT_TELEGRAM_BOT_TOKEN", "")
ALERT_TELEGRAM_CHAT_ID = os.getenv("ALERT_TELEGRAM_CHAT_ID", "")
ALERT_WEBHOOK_SECRET = os.getenv("ALERT_WEBHOOK_SECRET", "")

MAX_RETRIES = 3
RETRY_BASE_DELAY = 1.0


def _retry(func, *args, max_retries=MAX_RETRIES, **kwargs):
    last_exc = None
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            last_exc = e
            delay = RETRY_BASE_DELAY * (2 ** attempt)
            logger.warning(
                "dispatch attempt %d failed: %s, retrying in %.1fs",
                attempt + 1,
                e,
                delay,
            )
            time.sleep(delay)
    logger.error("dispatch failed after %d retries: %s", max_retries, last_exc)
    raise last_exc


def _record_history(severity, title, message, source, channel_type, status, metadata=None):
    try:
        AlertHistory.objects.create(
            severity=severity,
            title=title,
            message=message,
            source=source,
            channel=channel_type,
            status=status,
            metadata=metadata or {},
        )
    except Exception as e:
        logger.error("failed to record alert history: %s", e)


def _send_email(channel_config, subject, body):
    smtp_host = channel_config.get("host", ALERT_EMAIL_HOST)
    smtp_port = int(channel_config.get("port", ALERT_EMAIL_PORT))
    smtp_user = channel_config.get("user", ALERT_EMAIL_USER)
    smtp_pass = channel_config.get("password", ALERT_EMAIL_PASSWORD)
    smtp_from = channel_config.get("from", ALERT_EMAIL_FROM)
    use_tls = channel_config.get("use_tls", ALERT_EMAIL_USE_TLS)
    recipients = channel_config.get("recipients", [])

    if not recipients:
        logger.warning("no email recipients configured")
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_from
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(body, "plain"))

    def _do_send():
        server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
        try:
            if use_tls:
                server.starttls()
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_from, recipients, msg.as_string())
        finally:
            server.quit()

    _retry(_do_send)
    logger.info("email sent to %s", recipients)


def _send_telegram(channel_config, text):
    bot_token = channel_config.get("bot_token", ALERT_TELEGRAM_BOT_TOKEN)
    chat_id = channel_config.get("chat_id", ALERT_TELEGRAM_CHAT_ID)

    if not bot_token or not chat_id:
        logger.warning("telegram bot_token or chat_id not configured")
        return

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

    def _do_send():
        resp = requests.post(
            url,
            json={"chat_id": chat_id, "text": text, "parse_mode": "HTML"},
            timeout=10,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"telegram API error {resp.status_code}: {resp.text}")

    _retry(_do_send)
    logger.info("telegram message sent to chat_id=%s", chat_id)


def _send_webhook(channel_config, payload):
    webhook_url = channel_config.get("url", "")
    webhook_secret = channel_config.get("secret", ALERT_WEBHOOK_SECRET)

    if not webhook_url:
        logger.warning("webhook URL not configured")
        return

    body = json.dumps(payload, default=str)
    headers = {"Content-Type": "application/json"}
    if webhook_secret:
        signature = hmac.new(
            webhook_secret.encode(), body.encode(), hashlib.sha256
        ).hexdigest()
        headers["X-Webhook-Signature"] = signature

    def _do_send():
        resp = requests.post(webhook_url, data=body, headers=headers, timeout=15)
        if resp.status_code >= 400:
            raise RuntimeError(f"webhook error {resp.status_code}: {resp.text}")

    _retry(_do_send)
    logger.info("webhook sent to %s", webhook_url)


def dispatch_alert(
    severity: str,
    title: str,
    message: str,
    source: str = "",
    metadata: dict = None,
):
    channels = AlertChannel.objects.filter(is_active=True)
    dispatched = 0

    for channel in channels:
        severity_filter = channel.severity_filter or []
        if severity_filter and severity not in severity_filter:
            continue

        channel_type = channel.channel_type
        config = channel.config or {}
        subject = f"[VANT-SIEM {severity.upper()}] {title}"

        try:
            if channel_type == "email":
                _send_email(config, subject, message)
            elif channel_type == "telegram":
                telegram_text = (
                    f"<b>VANT-SIEM Alert</b>\n"
                    f"Severity: <b>{severity.upper()}</b>\n"
                    f"Title: {title}\n"
                    f"Source: {source}\n\n"
                    f"{message}"
                )
                _send_telegram(config, telegram_text)
            elif channel_type == "webhook":
                payload = {
                    "severity": severity,
                    "title": title,
                    "message": message,
                    "source": source,
                    "metadata": metadata or {},
                    "timestamp": time.time(),
                }
                _send_webhook(config, payload)

            _record_history(severity, title, message, source, channel_type, "sent", metadata)
            dispatched += 1

        except Exception as e:
            logger.error(
                "dispatch failed channel=%s type=%s error=%s",
                channel.name,
                channel_type,
                e,
            )
            _record_history(
                severity, title, message, source, channel_type, "failed",
                {"error": str(e), **(metadata or {})},
            )

    return dispatched
