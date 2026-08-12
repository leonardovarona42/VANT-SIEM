# vant-soar

Servicio de **SOAR** (Security Orchestration, Automation and Response) con motor de **machine learning** para predecir incidentes a partir del trafico de red y generar **respuesta automatica** (reportes SOC).

- Puerto: **8800**
- Base de datos: `vant_soar`
- Prefijo URL: `/api/`

## Descripcion

Analiza eventos de `logs_events_raw` (firewalls, Suricata), construye **features por IP origen**, genera **predicciones de riesgo** (score y decision: investigate/block) y, en modo automatico, publica las predicciones al bus para que el SOC cree reportes sin intervencion humana. Incluye reentrenamiento con sklearn y playbooks.

## Estructura

```
vant-soar/
├── config/
├── soar_app/
│   ├── management/commands/
│   │   ├── run_worker.py    # worker incremental (poll + batch)
│   │   ├── seed_ports.py    # sembrar puertos criticos / trojan-C2
│   │   └── train_model.py   # entrenar modelo ML
│   ├── db_router.py
│   ├── services.py          # motor SOAR (parser, features, reglas, publish)
│   ├── models.py            # 9 modelos (ver abajo)
│   ├── views.py
│   ├── serializers.py
│   └── urls.py
├── models/                  # modelos entrenados (joblib) - no versionados
└── manage.py
```

## Modelos

| Modelo | Funcion |
|--------|---------|
| `SoarConfig` | Configuracion (modo predict, umbrales, create_report_in_soc) |
| `ThreatPort` | Puertos de amenaza conocidos |
| `CriticalPort` | Puertos criticos de la red |
| `SoarModel` | Registro de modelos ML entrenados |
| `NetworkFeature` | Features por IP/ventana (incluye `msg`) |
| `SoarPrediction` | Prediccion (ip, score, risk_level, decision, status, evidence) |
| `FeedbackLabel` | Feedback del analista (confirmed / false_positive) |
| `Playbook` | Playbooks de respuesta |
| `PlaybookRun` | Ejecuciones de playbooks |

## Pipeline

```
logs_events_raw (vant_logs)
        │  (consulta por ventana)
        ▼
NetworkFeature  --features por IP origen-->  [rules + modelo ML]
        │
        ▼
SoarPrediction  (score, risk_level, decision)
        │
        ├─ mode=suggest : solo se registra
        ├─ mode=automatic: publica a Redis stream 'threats'
        │        └─> vantsiem-soc-soar -> crea Reporte SOC (nombre_informante='SOAR Automatico')
        └─ registra SystemEvent en vant-bus (event_type=incidente_creado)
```

- **Reglas heurísticas**: `attack_type` (BRUTE_FORCE, DDoS, PORT_SCAN, POLICY_DENY), puertos criticos/trojan, bursts. El `attack_type` inicial se aprende de trafico real.
- **Solo IPs externas**: se predice sobre IPs externas (atacantes); las internas solo aportan features.
- **Modelo ML**: `sklearn` (GBDT por defecto), persistido con joblib, reentrenable desde `POST /api/retrain/`.

## Endpoints

| Ruta | Metodo | Funcion |
|------|--------|---------|
| `/api/health/` | GET | Health check |
| `/api/config/` | GET/PATCH | Ver/actualizar configuracion (modo, umbrales) |
| `/api/threat-ports/` | GET | Puertos de amenaza |
| `/api/critical-ports/` | GET | Puertos criticos |
| `/api/predictions/` | GET | Listar predicciones (`?limit=` para paginar) |
| `/api/predictions/<pk>/` | GET | Detalle de prediccion |
| `/api/predictions/<pk>/feedback/` | POST | Registrar feedback (confirmed/false_positive) |
| `/api/predictions/<pk>/act/` | POST | Accion de respuesta |
| `/api/features/` | GET | Features calculadas |
| `/api/models/` | GET | Modelos registrados |
| `/api/playbooks/` | GET | Playbooks |
| `/api/playbook-runs/` | GET | Ejecuciones |
| `/api/stats/` | GET | Estadisticas (totales, por riesgo, config) |
| `/api/analyze/` | POST | Analisis puntual (o simulacion con `simulate`) |
| `/api/retrain/` | POST | Reentrenar modelo (`model_name=incident_risk`) |

## Comandos de gestion

| Comando | Uso |
|---------|-----|
| `python manage.py run_worker --poll 5 --batch 500` | Worker incremental (unidad `vantsiem-soar-worker`) |
| `python manage.py seed_ports` | Sembrar puertos criticos (16) y trojan/C2 (10) |
| `python manage.py train_model` | Entrenar modelo ML |

## Unidades systemd

| Unidad | Descripcion |
|--------|-------------|
| `vantsiem-soar` | gunicorn API SOAR (:8800) |
| `vantsiem-soar-worker` | `run_worker --poll 5 --batch 500` |
| `vantsiem-soc-soar` | Consumidor SOC (en `vant-soc`) que crea reportes |

Logs: `/var/log/vant/soar.log`, `/var/log/vant/soar-worker.log`, `/var/log/vant/soc-soar.log`.

## Configuracion

| Variable | Uso |
|----------|-----|
| `SOAR_SERVICE_URL` | URL interna (`http://127.0.0.1:8800`) |
| `REDIS_URL` | Broker para publicar al stream `threats` (`redis://127.0.0.1:6379/0`) |
| `SERVICE_SECRET` | Autorizacion interna |

Configuracion runtime en BD (`SoarConfig`): `prediction_mode` (suggest/automatic/off), `report_threshold`, `block_threshold`, `high_threshold`, `medium_threshold`, `create_report_in_soc`, `enabled`.

## Integracion

- **Entrada**: lee `logs_events_raw` de `vant-logs`.
- **Salida**: stream Redis `threats` -> `vant-soc` (reportes); `SystemEvent` -> `vant-bus`.
- **UI**: dashboard SOAR en `vant-web` (`/siem/dashboard/inteligencia/soar/`) que proxya a esta API.
