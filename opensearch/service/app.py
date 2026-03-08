from flask import Flask, jsonify, request

from config import Settings
from db import save_events, upsert_source

app = Flask(__name__)


def _is_authorized(req):
    mode = Settings.AUTH_MODE
    if mode == "none":
        return True

    if mode == "basic":
        auth = req.authorization
        if not auth:
            return False
        return auth.username == Settings.AUTH_USERNAME and auth.password == Settings.AUTH_PASSWORD

    if mode == "token":
        hdr = req.headers.get("Authorization", "")
        if not hdr.startswith("Bearer "):
            return False
        token = hdr.replace("Bearer ", "", 1).strip()
        return token == Settings.AUTH_TOKEN

    return False


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "opensearch-service"})


@app.post("/api/v1/sources/upsert")
def sources_upsert():
    if not _is_authorized(request):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    payload = request.get_json(silent=True) or {}
    if "source_id" not in payload:
        return jsonify({"ok": False, "error": "source_id required"}), 400
    row = upsert_source(payload)
    return jsonify({"ok": True, "source": row})


@app.post("/api/v1/events/bulk")
def events_bulk():
    if not _is_authorized(request):
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    payload = request.get_json(silent=True) or {}
    events = payload.get("events", [])
    if not isinstance(events, list):
        return jsonify({"ok": False, "error": "events must be a list"}), 400

    inserted = save_events(events)
    return jsonify({"ok": True, "inserted": inserted})


if __name__ == "__main__":
    app.run(host=Settings.SERVICE_HOST, port=Settings.SERVICE_PORT)

