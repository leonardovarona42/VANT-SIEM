import hashlib
import json
import logging
import os
import re
import socket
import time
from collections import defaultdict
from datetime import datetime, timedelta

import requests
from django.conf import settings
from django.db import connections
from django.utils import timezone

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

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constantes / heurísticas base
# ---------------------------------------------------------------------------

INTERNAL_PREFIXES = ("10.", "127.", "192.168.", "169.254.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3", "172.4", "172.5", "172.6", "172.7", "172.8", "172.9", "172.1", "::1", "fe80:")
"""Prefijos RFC1918/link-local. 172.1-172.31 cubiertos via netmask exacto en _is_rfc1918."""

DEFAULT_CRITICAL_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    139: "NetBIOS",
    3389: "RDP",
    5900: "VNC",
    445: "SMB",
    135: "MS-RPC",
    1433: "MSSQL",
    5432: "PostgreSQL",
    3306: "MySQL",
    1521: "Oracle",
    6379: "Redis",
    9200: "Elasticsearch",
    5985: "WinRM",
    5986: "WinRM-HTTPS",
}

DEFAULT_TROJAN_PORTS = {
    4444: "Metasploit default listener",
    5555: "Android ADB / malware",
    6666: "IRC botnet (historic)",
    6667: "IRC botnet C2",
    7777: "Trojan / proxy",
    10080: "Amanda / trojan",
    12345: "NetBus trojan",
    31337: "Back Orifice",
    41170: "Trojan",
    65000: "Trojan",
}


def _is_rfc1918(ip: str) -> bool:
    if not ip:
        return False
    try:
        import ipaddress
    except ImportError:  # pragma: no cover
        return ip.startswith(INTERNAL_PREFIXES)
    try:
        return ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_link_local
    except ValueError:
        return ip.startswith(INTERNAL_PREFIXES)


def is_internal_ip(ip: str) -> bool:
    if not ip:
        return False
    if _is_rfc1918(ip):
        return True
    return ip in _fetch_our_ips()


_our_ips_cache = {"ts": 0.0, "ips": set()}


def _fetch_our_ips(ttl=300.0):
    """IPs y rangos propios según soc_servicio_ips + soc_servicios (vant_soc)."""
    now = time.monotonic()
    if now - _our_ips_cache["ts"] < ttl:
        return _our_ips_cache["ips"]
    ips = set()
    try:
        with connections["vant_soc"].cursor() as cur:
            cur.execute("SELECT ip_address FROM soc_servicio_ips")
            for (ip,) in cur.fetchall():
                if ip:
                    ips.add(str(ip).strip())
            cur.execute("SELECT network, subnet_mask FROM soc_servicios WHERE network IS NOT NULL")
            for net, mask in cur.fetchall():
                if not net:
                    continue
                if mask in (None, "", 0, "0", "0.0.0.0"):
                    ips.add(str(net).strip())
                else:
                    try:
                        import ipaddress

                        net = ipaddress.ip_network(f"{net}/{mask}", strict=False)
                        for n in net.hosts():
                            ips.add(str(n))
                            if len(ips) > 4000:
                                break
                    except ValueError:
                        ips.add(str(net).strip())
    except Exception as exc:  # conexión, tablas inexistentes...
        logger.debug("No se pudo leer soc_servicio_ips: %s", exc)
    _our_ips_cache["ts"] = now
    _our_ips_cache["ips"] = ips
    return ips


# ---------------------------------------------------------------------------
# Acceso a datos (vant_logs)
# ---------------------------------------------------------------------------

EVENT_TABLE = "logs_events_raw"


def iter_events_since(cursor_id, limit=500):
    """Itera LogEventRaw desde id > cursor_id (vant_logs).

    Esquema real: id, source_type, host_name, host_ip, event_time, severity,
    event_category, message, raw_payload (jsonb), parsed_fields (jsonb),
    tags, ingested_at, source_id.
    """
    with connections["vant_logs"].cursor() as cur:
        cur.execute(
            f"SELECT id, event_time, source_type, event_category, raw_payload "
            f"FROM {EVENT_TABLE} WHERE id > %s ORDER BY id ASC LIMIT %s",
            [cursor_id, limit],
        )
        for row in cur.fetchall():
            yield {
                "id": row[0],
                "timestamp": row[1],
                "event_type": row[2] or row[3],
                "raw_payload": row[4],
            }


def get_recent_raw_events(minutes=15, limit=1000):
    """Para diagnósticos: últimos eventos sin tocar la base de SOAR (lista de dicts)."""
    since = timezone.now() - timedelta(minutes=minutes)
    with connections["vant_logs"].cursor() as cur:
        cur.execute(
            f"SELECT id, event_time, source_type, event_category, raw_payload "
            f"FROM {EVENT_TABLE} WHERE event_time >= %s ORDER BY event_time DESC LIMIT %s",
            [since, limit],
        )
        return [
            {
                "id": r[0],
                "timestamp": r[1],
                "event_type": r[2] or r[3],
                "raw_payload": r[4],
            }
            for r in cur.fetchall()
        ]


_LINE_KV_RE = re.compile(r"(\w+)=([^\s,]+)")


def _parse_line_kv(text: str) -> dict:
    """Extrae pares key=value de logs tipo firewall Huawei (Eudemon1000E)."""
    out = {}
    for key, val in _LINE_KV_RE.findall(text or ""):
        if key not in out:
            out[key] = val
    return out


def _extract_flow(event) -> tuple | None:
    """Extrae (src_ip, dst_ip, src_port, dst_port, proto, msg).

    Soporta:
    - JSON estructurado tipo Suricata/eve (src_ip/dest_ip/...)
    - Logs de firewall con el texto en 'line' (key=value)
    """
    try:
        if isinstance(event.get("raw_payload"), dict):
            pf = event["raw_payload"]
        else:
            pf = json.loads(event.get("raw_payload") or "{}")
    except (TypeError, ValueError):
        pf = {}
    if not isinstance(pf, dict):
        return None

    if isinstance(pf.get("line"), str):
        kv = _parse_line_kv(pf["line"])
        src_ip = kv.get("src_ip")
        dst_ip = kv.get("dst_ip")
        if not src_ip or not dst_ip:
            return None
        try:
            src_port = int(kv.get("src_port") or 0)
        except ValueError:
            src_port = 0
        try:
            dst_port = int(kv.get("dst_port") or 0)
        except ValueError:
            dst_port = 0
        proto = kv.get("protocol") or kv.get("proto") or "unknown"
        msg = kv.get("attack_type") or kv.get("policy") or kv.get("service") or ""
        return (str(src_ip), str(dst_ip), src_port, dst_port, proto, msg)

    src_ip = pf.get("src_ip") or pf.get("source_ip")
    dst_ip = pf.get("dest_ip") or pf.get("dst_ip")
    if not src_ip or not dst_ip:
        return None
    return (
        str(src_ip),
        str(dst_ip),
        pf.get("src_port") or 0,
        pf.get("dest_port") or pf.get("dst_port") or 0,
        (pf.get("proto") or pf.get("protocol") or "unknown"),
        pf.get("msg") or pf.get("alert", {}).get("signature") if isinstance(pf.get("alert"), dict) else (pf.get("msg") or ""),
    )


# ---------------------------------------------------------------------------
# Feature builder
# ---------------------------------------------------------------------------

class _AggCounter:
    __slots__ = ("conn", "inbound", "outbound", "syn", "dst", "ports", "protos", "internal_dst", "external_dst", "critical", "trojan", "msg_hint", "start", "last")

    def __init__(self, ts):
        self.conn = 0
        self.inbound = 0
        self.outbound = 0
        self.syn = 0
        self.dst = defaultdict(int)
        self.ports = set()
        self.protos = set()
        self.internal_dst = 0
        self.external_dst = 0
        self.critical = set()
        self.trojan = set()
        self.msg_hint = ""
        self.start = ts
        self.last = ts


def build_network_features(events, cfg: SoarConfig, window_start=None, window_end=None):
    """Agrega eventos a features por IP. Devuelve lista de dicts listos para persistir."""
    now = timezone.now()
    window_start = window_start or (now - timedelta(minutes=cfg.window_minutes))
    window_end = window_end or now

    critical = {p.port for p in CriticalPort.objects.filter(is_active=True)} or set(DEFAULT_CRITICAL_PORTS)
    trojan = {p.port for p in ThreatPort.objects.filter(is_active=True)} or set(DEFAULT_TROJAN_PORTS)
    our_ips = _fetch_our_ips()

    by_ip = {}
    for ev in events:
        flow = _extract_flow(ev)
        if not flow:
            continue
        src_ip, dst_ip, src_port, dst_port, proto, msg = flow
        ts = ev.get("timestamp") or now

        # Consideramos al origen como candidato a analizar; también el destino si es interno.
        for ip, role in ((src_ip, "src"), (dst_ip, "dst")):
            agg = by_ip.setdefault(ip, _AggCounter(ts))
            agg.conn += 1
            agg.start = min(agg.start, ts)
            agg.last = max(agg.last, ts)
            if role == "src":
                agg.outbound += 1
            else:
                agg.inbound += 1
            if isinstance(proto, str) and proto.lower() in ("tcp", "syn", "tcp-syn"):
                agg.syn += 1
            if dst_port:
                agg.ports.add(int(dst_port))
                if int(dst_port) in critical:
                    agg.critical.add(int(dst_port))
                if int(dst_port) in trojan:
                    agg.trojan.add(int(dst_port))
            if isinstance(dst_ip, str):
                if is_internal_ip(dst_ip):
                    agg.internal_dst += 1
                else:
                    agg.external_dst += 1
            if isinstance(dst_ip, str):
                agg.dst[dst_ip] += 1
            if isinstance(src_port, str):
                try:
                    agg.ports.add(int(src_port))
                except ValueError:
                    pass
            if proto:
                agg.protos.add(str(proto).lower())
            if msg and not agg.msg_hint:
                agg.msg_hint = str(msg)[:200]

    features = []
    for ip, agg in by_ip.items():
        if not ip:
            continue
        is_int = is_internal_ip(ip)
        total_dst = agg.internal_dst + agg.external_dst
        features.append(
            {
                "ip": ip,
                "is_internal": is_int,
                "window_start": window_start,
                "window_end": window_end,
                "conn_count": agg.conn,
                "inbound_count": agg.inbound,
                "outbound_count": agg.outbound,
                "distinct_dst_ips": len(agg.dst),
                "distinct_dst_ports": len(agg.ports),
                "distinct_protos": len(agg.protos),
                "critical_port_access": bool(agg.critical),
                "trojan_port_hit": bool(agg.trojan),
                "burst_same_dst": max(agg.dst.values()) if agg.dst else 0,
                "burst_targets": total_dst,
                "internal_targets": agg.internal_dst,
                "external_targets": agg.external_dst,
                "syn_count": agg.syn,
                "msg_hint": agg.msg_hint,
                "_critical_ports": sorted(agg.critical),
                "_trojan_ports": sorted(agg.trojan),
            }
        )
    return features


# ---------------------------------------------------------------------------
# Scoring: heurísticas + modelo ML
# ---------------------------------------------------------------------------

def _get_active_model(name="incident_risk"):
    return SoarModel.objects.filter(name=name, is_active=True).order_by("-version").first()


def rule_based_score(f: dict, cfg: SoarConfig) -> tuple[float, list]:
    """Score 0-1 heurístico y evidencias. Es el fallback y el baseline."""
    score = 0.0
    evidence = []

    msg = (f.get("msg_hint") or "").upper()

    # Clasificación de ataque ya hecha por el firewall (Eudemon1000E)
    if "BRUTE_FORCE" in msg or "BRUTEFORCE" in msg:
        score += 0.55
        evidence.append({"rule": "attack_type", "detail": f"Brute force: {f.get('msg_hint')}"})
    if "DDoS" in msg:
        score += 0.50
        evidence.append({"rule": "attack_type", "detail": f"DDoS: {f.get('msg_hint')}"})
    if "PORT_SCAN" in msg or "SCAN" in msg:
        score += 0.40
        evidence.append({"rule": "attack_type", "detail": f"Escaneo: {f.get('msg_hint')}"})
    if "POLICY/DENY" in msg or "POLICY" in msg:
        score += 0.15
        evidence.append({"rule": "policy_deny", "detail": f"Denegado por política: {f.get('msg_hint')}"})

    if f.get("trojan_port_hit"):
        score += 0.45
        evidence.append({"rule": "trojan_port", "detail": f"Puertos de trojan/C2: {f.get('_trojan_ports')}"})

    if f.get("critical_port_access"):
        score += 0.35
        evidence.append({"rule": "critical_port", "detail": f"Acceso a puertos críticos: {f.get('_critical_ports')}"})

    if f.get("is_internal"):
        score -= 0.20
        evidence.append({"rule": "internal_ip", "detail": "Origen interno (menor prioridad)"})

    burst_same = f.get("burst_same_dst") or 0
    burst_targets = f.get("burst_targets") or 0
    if burst_same >= cfg.burst_same_dst_threshold:
        score += 0.25
        evidence.append({"rule": "burst_same_dst", "detail": f"{burst_same} conexiones al mismo destino"})
    if burst_targets >= cfg.burst_targets_threshold:
        score += 0.30
        evidence.append({"rule": "burst_targets", "detail": f"{burst_targets} destinos distintos (scan)"})

    total = f.get("conn_count") or 0
    if total > 100:
        score += 0.15
        evidence.append({"rule": "volume", "detail": f"{total} conexiones en la ventana"})
    elif total > 30:
        score += 0.05

    syn = f.get("syn_count") or 0
    if total and syn / total > 0.6 and total > 5:
        score += 0.15
        evidence.append({"rule": "syn_flood", "detail": f"Alto ratio SYN ({syn}/{total})"})

    if f.get("abuse_score", 0) >= 80:
        score += 0.20
        evidence.append({"rule": "abuseipdb", "detail": f"Confidence {f.get('abuse_score')} en AbuseIPDB"})
    elif f.get("abuse_score", 0) >= 40:
        score += 0.08

    return round(max(0.0, min(1.0, score)), 4), evidence


class _SklearnModel:
    """Wrapper sobre un modelo sklearn serializado (joblib/pickle) en models/."""

    def __init__(self, file_path, feature_names, is_prob=True):
        self.feature_names = feature_names or []
        self.is_prob = is_prob
        try:
            import joblib  # type: ignore
        except ImportError:
            joblib = None
        self._clf = joblib.load(file_path) if joblib else None

    def predict_proba(self, vector):
        if self._clf is None:
            return None
        x = [[vector.get(n, 0.0) for n in self.feature_names]]
        try:
            if self.is_prob and hasattr(self._clf, "predict_proba"):
                proba = self._clf.predict_proba(x)[0]
                if self._clf.classes_[-1] == 1 or self._clf.classes_[-1] == 1.0:
                    return float(proba[-1])
                if len(proba) == 2:
                    return float(proba[1])
                return float(max(proba))
            return float(self._clf.predict(x)[0])
        except Exception as exc:
            logger.warning("Fallo predict sklearn: %s", exc)
            return None


def _load_ml_model() -> _SklearnModel | None:
    model = _get_active_model()
    if model is None or model.framework not in ("sklearn", "keras", "tflite") or not model.file_path:
        return None
    path = model.file_path
    if not os.path.isabs(path):
        path = str(settings.SOAR_MODELS_DIR / path)
    if not os.path.exists(path):
        logger.warning("Modelo %s no encontrado en %s", model.name, path)
        return None
    if model.framework == "sklearn":
        return _SklearnModel(path, model.feature_names)
    # keras / tflite: se integran aquí cuando existan artefactos
    logger.warning("Framework %s aún no soportado en runtime", model.framework)
    return None


def predict_score(features: dict, cfg: SoarConfig):
    """Combina heurísticas con el modelo ML activo (si hay)."""
    rules, evidence = rule_based_score(features, cfg)
    model = _load_ml_model()
    ml_score = None
    framework = "rules"
    model_version = 0
    if model is not None:
        ml_score = model.predict_proba(features)
        framework = "sklearn"
        model_version = _get_active_model().version if _get_active_model() else 0
    if ml_score is None:
        final = rules
    else:
        final = 0.7 * float(ml_score) + 0.3 * rules
        evidence.append({"rule": "ml_model", "detail": f"ML score {ml_score:.3f} ({framework} v{model_version})"})
    return round(max(0.0, min(1.0, final)), 4), evidence, framework, model_version


def risk_level_for(score: float, cfg: SoarConfig) -> str:
    if score >= cfg.block_threshold:
        return "critical"
    if score >= cfg.high_threshold:
        return "high"
    if score >= cfg.medium_threshold:
        return "medium"
    return "low"


def decision_for(risk: str) -> str:
    return {
        "critical": "block",
        "high": "investigate",
        "medium": "monitor",
        "low": "allow",
    }[risk]


# ---------------------------------------------------------------------------
# Integración con el bus y SOC
# ---------------------------------------------------------------------------

def _bus_url() -> str:
    return os.getenv("BUS_URL", "http://127.0.0.1:8600").rstrip("/")


def _service_secret() -> str:
    return os.getenv("SERVICE_SECRET", "")


def publish_bus_event(stream_key: str, event_type: str, data: dict) -> str:
    """Publica en el bus central.

    Hace dos cosas:
    1) Publica en el stream Redis indicado ('threats'/'alerts'/'commands') usando
       vant_common.bus.EventBus, que es lo que consumen los workers (p. ej. SOC).
    2) Registra un SystemEvent en vant-bus (HTTP) para que el evento aparezca en
       el dashboard de Eventos.
    """
    event_id = ""
    try:
        from vant_common.bus import EventBus

        bus = EventBus("vant-soar")
        event_id = str(bus.publish_event(stream_key, event_type, data))
    except Exception as exc:
        logger.warning("Fallo publish Redis stream '%s': %s", stream_key, exc)

    try:
        headers = {}
        secret = _service_secret()
        if secret:
            headers["X-Service-Secret"] = secret
        resp = requests.post(
            f"{_bus_url()}/api/events/receive/",
            json={
                "event_type": "incidente_creado",
                "source_service": "vant-soar",
                "entity_type": "ip",
                "entity_id": str(data.get("ip") or ""),
                "actor_username": "SOAR",
                "payload": {"soar_event": event_type, "data": data},
                "severity": data.get("risk") or "medium",
            },
            headers=headers,
            timeout=8,
        )
        if resp.status_code == 201:
            logger.debug("SystemEvent registrado en el bus: %s", resp.status_code)
        elif resp.status_code != 401:
            logger.warning("Bus SystemEvent devolvió %s: %s", resp.status_code, resp.text[:200])
    except Exception as exc:
        logger.warning("Fallo SystemEvent en bus: %s", exc)
    return event_id


def _soc_url() -> str:
    return os.getenv("SOC_URL", "http://127.0.0.1:8400").rstrip("/")


def _report_description(prediction: SoarPrediction) -> str:
    features = prediction.features or {}
    msg = (features.get("msg_hint") or "")[:400]
    return (
        f"[SOAR] Detección automática - IP {prediction.ip}\n"
        f"Score: {prediction.score:.2f} | Riesgo: {prediction.risk_level}\n"
        f"Decision: {prediction.decision}\n"
        f"Evidencia: {json.dumps(prediction.evidence or [], ensure_ascii=False)[:800]}\n"
        f"Detalle red: {msg}"
    )


def create_soc_report(prediction: SoarPrediction, cfg: SoarConfig) -> str:
    """Crea un reporte en vant-soc con la info de la predicción (modo automático)."""
    payload = {
        "nombre_informante": cfg.report_informante,
        "email_informante": "",
        "area": "SOAR",
        "area_nombre": "Seguridad (SOAR)",
        "descripcion": _report_description(prediction),
        "fecha_hora": timezone.now().isoformat(),
    }
    try:
        headers = {}
        secret = _service_secret()
        if secret:
            headers["X-Service-Secret"] = secret
        resp = requests.post(f"{_soc_url()}/api/incidentes/", json=payload, headers=headers, timeout=8)
        if resp.status_code in (200, 201):
            body = resp.json()
            return str(body.get("id") or "")
        logger.warning("SOC reporte devolvió %s: %s", resp.status_code, resp.text[:300])
    except Exception as exc:
        logger.exception("Fallo al crear reporte en SOC: %s", exc)
    return ""


# ---------------------------------------------------------------------------
# Orquestación
# ---------------------------------------------------------------------------

def run_playbook_for(prediction: SoarPrediction, cfg: SoarConfig):
    """Ejecuta el playbook activo cuyo umbral coincida."""
    playbook = (
        Playbook.objects.filter(is_active=True, trigger_risk_level=prediction.risk_level)
        .filter(trigger_min_score__lte=prediction.score)
        .order_by("-trigger_min_score")
        .first()
    )
    run = PlaybookRun.objects.create(
        playbook=playbook,
        prediction=prediction,
        status="running",
        steps_log=[],
    )
    steps = playbook.actions if playbook else []
    log = []
    for step in steps:
        step_type = step.get("type") if isinstance(step, dict) else step
        result = {"step": step_type, "ok": False}
        try:
            if step_type == "bus_alert":
                eid = publish_bus_event("alerts", "soar_alert", {
                    "ip": prediction.ip,
                    "score": prediction.score,
                    "risk": prediction.risk_level,
                    "evidence": prediction.evidence,
                })
                result = {"step": "bus_alert", "ok": True, "event_id": eid}
            elif step_type == "soc_report":
                if prediction.soc_report_id:
                    result = {"step": "soc_report", "ok": True, "detail": "ya creado via bus", "report_id": prediction.soc_report_id}
                else:
                    rid = create_soc_report(prediction, cfg)
                    result = {"step": "soc_report", "ok": bool(rid), "report_id": rid}
            elif step_type == "log":
                logger.info("[PLAYBOOK] %s: %s", prediction.ip, prediction.evidence)
                result = {"step": "log", "ok": True}
            # 'block' (iptables/API FW) se deja como stub a implementar por equipo
            elif step_type == "block":
                result = {"step": "block", "ok": False, "detail": "Acción bloqueo no configurada (stub)"}
            else:
                result = {"step": str(step_type), "ok": False, "detail": "Paso desconocido"}
        except Exception as exc:
            result["error"] = str(exc)
        log.append(result)
    run.steps_log = log
    run.status = "completed" if all(s.get("ok") for s in log) else "failed"
    run.completed_at = timezone.now()
    run.save()
    return run


def analyze_and_act(events, cfg: SoarConfig, source_event_ids=None) -> list[SoarPrediction]:
    """Pipeline: features -> score -> predicción -> acción segura el modo."""
    if not cfg.enabled:
        return []
    features = build_network_features(events, cfg)
    predictions = []
    for f in features:
        # Solo predecimos sobre IPs externas (candidatos a atacantes). Los hosts
        # internos quedan como features para contexto, no como predicciones.
        if f["is_internal"]:
            continue
        score, evidence, framework, mver = predict_score(f, cfg)
        risk = risk_level_for(score, cfg)
        if score < cfg.report_threshold:
            continue  # bajo umbral: solo feature
        feat = {
            k: v for k, v in f.items()
            if not k.startswith("_") and k not in ("msg_hint", "window_start", "window_end")
        }
        feat["msg"] = f.get("msg_hint") or ""
        pred = SoarPrediction.objects.create(
            ip=f["ip"],
            score=score,
            risk_level=risk,
            decision=decision_for(risk),
            status="new",
            model_version=mver,
            model_framework=framework,
            features=feat,
            evidence=evidence,
            source_event_ids=source_event_ids or [],
        )
        # Persistimos también la feature agregada
        NetworkFeature.objects.update_or_create(
            ip=f["ip"], window_start=f["window_start"],
            defaults={**feat, "window_end": f["window_end"], "score": score, "risk_level": risk},
        )
        if cfg.prediction_mode == "automatic":
            if risk in ("high", "critical"):
                descripcion = _report_description(pred)
                pred.bus_event_id = publish_bus_event("threats", "soar_prediction", {
                    "ip": f["ip"],
                    "score": score,
                    "risk": risk,
                    "decision": pred.decision,
                    "prediction_id": pred.id,
                    "descripcion": descripcion,
                })
                # Fallback: si el bus no responde, crear el reporte directo
                if cfg.create_report_in_soc and not pred.bus_event_id:
                    pred.soc_report_id = create_soc_report(pred, cfg)
            run_playbook_for(pred, cfg)
        else:
            # modo suggest: avisamos al bus sin tocar SOC
            if risk in ("high", "critical"):
                pred.bus_event_id = publish_bus_event("alerts", "soar_suggestion", {
                    "ip": f["ip"], "score": score, "risk": risk, "prediction_id": pred.id,
                })
        pred.analyzed_at = timezone.now()
        pred.save()
        predictions.append(pred)
    return predictions


# ---------------------------------------------------------------------------
# Feedback / retraining
# ---------------------------------------------------------------------------

def label_prediction(prediction: SoarPrediction, label: str, notes="", created_by=""):
    fb = FeedbackLabel.objects.create(
        prediction=prediction, label=label, notes=notes, created_by=created_by,
    )
    prediction.status = "confirmed" if label == "confirmed" else "false_positive"
    prediction.feedback_note = notes or prediction.feedback_note
    prediction.save()
    return fb


def collect_training_samples(samples_limit=0):
    """Convierte features+feedback en pares (X, y) para reentrenar."""
    import itertools

    rows = NetworkFeature.objects.select_related().all().order_by("-updated_at")
    if samples_limit:
        rows = rows[:samples_limit]
    X, y, feature_names = [], [], []
    for feat in rows:
        preds = SoarPrediction.objects.filter(ip=feat.ip, status__in=("confirmed", "false_positive")).first()
        if preds is None:
            continue
        vector = {
            "conn_count": feat.conn_count, "inbound_count": feat.inbound_count,
            "outbound_count": feat.outbound_count, "distinct_dst_ips": feat.distinct_dst_ips,
            "distinct_dst_ports": feat.distinct_dst_ports, "distinct_protos": feat.distinct_protos,
            "critical_port_access": int(feat.critical_port_access), "trojan_port_hit": int(feat.trojan_port_hit),
            "burst_same_dst": feat.burst_same_dst, "burst_targets": feat.burst_targets,
            "internal_targets": feat.internal_targets, "external_targets": feat.external_targets,
            "syn_count": feat.syn_count, "abuse_score": feat.abuse_score,
        }
        feature_names = list(vector)
        X.append(list(vector.values()))
        y.append(1 if preds.status == "confirmed" else 0)
    return X, y, feature_names


def train_sklearn_model(model_name="incident_risk", samples_limit=0, xgb=True):
    """Entrena GradientBoosting o RandomForest y lo registra en SoarModel."""
    X, y, feature_names = collect_training_samples(samples_limit)
    if len(X) < 30:
        raise ValueError(
            f"Necesitas al menos 30 muestras etiquetadas (tienes {len(X)}). "
            "Marca predicciones como confirmado/falso positivo para mejorar."
        )
    import joblib
    from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
    from sklearn.metrics import accuracy_score, precision_score, recall_score
    from sklearn.model_selection import cross_val_score

    clf = (
        GradientBoostingClassifier(n_estimators=120, max_depth=4, learning_rate=0.08, random_state=42)
        if xgb else RandomForestClassifier(n_estimators=150, max_depth=8, random_state=42)
    )
    clf.fit(X, y)
    cv = cross_val_score(clf, X, y, cv=min(5, max(2, len(X) // 10)), scoring="roc_auc")
    y_pred = clf.predict(X)
    metrics = {
        "accuracy": round(accuracy_score(y, y_pred), 4),
        "precision": round(precision_score(y, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y, y_pred, zero_division=0), 4),
        "cv_roc_auc": round(float(cv.mean()), 4),
        "samples": len(X),
    }
    path = settings.SOAR_MODELS_DIR / f"{model_name}_{int(time.time())}.joblib"
    joblib.dump(clf, str(path))

    old = SoarModel.objects.filter(name=model_name, is_active=True)
    old.update(is_active=False)
    SoarModel.objects.create(
        name=model_name,
        framework="sklearn",
        version=old.count() + 1,
        file_path=path.name,
        metrics=metrics,
        trained_samples=len(X),
        feature_names=feature_names,
        is_active=True,
        trained_at=timezone.now(),
    )
    return metrics, len(X), feature_names


def simulate_traffic(duration_seconds=30, interval=1.0):
    """Genera eventos sintéticos para probar el pipeline sin tráfico real."""
    import random

    cfg = get_or_create_config()
    bots = ["203.0.113.10", "203.0.113.11", "198.51.100.7", "192.0.2.77", "45.155.205.100"]
    legit = ["8.8.8.8", "1.1.1.1", "104.16.132.229"]
    internal_hosts = ["192.168.12.43", "192.168.12.10", "192.168.12.25"]
    trojan_pick = [4444, 6667, 12345, 31337]
    critical_pick = [22, 3389, 445, 1433]

    events = []
    end = timezone.now() + timedelta(seconds=duration_seconds)
    while timezone.now() < end:
        payloads = []
        if random.random() < 0.35:  # bot scanning
            src = random.choice(bots)
            for _ in range(random.randint(5, 25)):
                dst = random.choice(internal_hosts + ["192.168.12." + str(random.randint(2, 200))])
                payloads.append({
                    "src_ip": src, "dest_ip": dst, "src_port": random.randint(40000, 65000),
                    "dest_port": random.choice(critical_pick + trojan_pick), "proto": "tcp",
                    "msg": "ET SCAN Possible SYN Scan",
                })
        else:  # tráfico legítimo
            src = random.choice(legit)
            payloads.append({
                "src_ip": src, "dest_ip": random.choice(internal_hosts),
                "src_port": random.randint(40000, 65000), "dest_port": 443, "proto": "tcp", "msg": "HTTPS",
            })
        for p in payloads:
            events.append({"timestamp": timezone.now(), "event_type": "flow", "raw_payload": json.dumps(p)})
        time.sleep(interval)
    return events
