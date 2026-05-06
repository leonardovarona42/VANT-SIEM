"""
VANT-SIEM Events
Event types used for inter-service communication
"""

# === Logs Service events ===
LOG_EVENT_RECEIVED = "log.event_received"
LOG_ALERT_TRIGGERED = "log.alert_triggered"
LOG_SERVICE_ERROR = "log.service_error"
LOG_SOURCE_REGISTERED = "log.source_registered"

# === Assets Service events ===
ASSET_ENROLLED = "asset.enrolled"
ASSET_HEARTBEAT = "asset.heartbeat"
ASSET_INVENTORY_UPDATED = "asset.inventory_updated"
ASSET_DLP_INCIDENT = "asset.dlp_incident"
ASSET_DLP_CONTAINED = "asset.dlp_contained"
ASSET_OFFLINE = "asset.offline"

# === Incidents Service events ===
INCIDENT_CREATED = "incident.created"
INCIDENT_UPDATED = "incident.updated"
INCIDENT_RESOLVED = "incident.resolved"
INCIDENT_ESCALATED = "incident.escalated"
INCIDENT_REPORT_GENERATED = "incident.report_generated"

# === AI Service events ===
AI_PREDICTION_CREATED = "ai.prediction_created"
AI_ANOMALY_DETECTED = "ai.anomaly_detected"
AI_MODEL_TRAINED = "ai.model_trained"
AI_FEEDBACK_RECEIVED = "ai.feedback_received"
