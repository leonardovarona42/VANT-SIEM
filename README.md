# 🛡️ VANT-SIEM
## Vigilance And Neutralization of Threats - Security Information & Event Management

<p align="center">
  <img src="https://img.shields.io/badge/Django-5.x-green?style=for-the-badge&logo=django" alt="Django">
  <img src="https://img.shields.io/badge/Python-3.12-blue?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/OpenSearch-2.x-orange?style=for-the-badge" alt="OpenSearch">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License">
</p>

---

## 📋 Descripción

**VANT-SIEM** es una plataforma de gestión de seguridad empresarial 🏢 de última generación, diseñada para la **detección**, **análisis** y **respuesta operativa** a incidentes de ciberseguridad. Combina las capacidades de un SIEM tradicional (eventos, alertas, investigación) con un pipeline moderno de logs basado en **OpenSearch** para lograr:

- ✅ **Visibilidad en tiempo real**
- ✅ **Trazabilidad completa**
- ✅ **Escalabilidad horizontal**
- ✅ **Cumplimiento normativo**

---

## 🧠 Ciberinteligencia y SOC de Nueva Generación

### 🤖 IA, Machine Learning y Analítica Predictiva

VANT-SIEM representa la evolución del concepto tradicional de SIEM hacia un **Sistema de Ciberinteligencia** de próxima generación. Esta no es simplemente una herramienta de registro de eventos, sino una **plataforma de análisis avanzado** que integra:

#### 🧠 Inteligencia Artificial
- **Análisis Comportamental**: Detección de anomalías mediante algoritmos de machine learning que identifican patrones de comportamiento sospechoso
- **Clasificación Automática**: Los incidentes son categorizados automáticamente según su naturaleza y severidad
- **Reducción de Falsos Positivos**: Los modelos predictivos aprenden de los patrones históricos para filtrar alertas ruido

#### 📊 Analítica Avanzada
- **Correlación Inteligente**: Relación de eventos aparentemente desconectados para descubrir ataques sofisticados
- **Análisis de Tendencias**: Visualización de patrones temporales para anticipar amenazas emergentes
- **Métricas de Seguridad**: KPIs y dashboards que proporcionan visibilidad del postura de seguridad organizacional

#### 🔮 Predicción y Prevención
- **Modelos Predictivos**: Algoritmos que anticipan posibles vectores de ataque basándose en inteligencia de amenazas
- **Evaluación de Riesgos**: Scoring dinámico de activos y vulnerabilidades
- ** Recomendaciones Automáticas**: Sugerencias de acciones de mitigación basadas en el análisis de incidentes similares

#### ⚡ Características Avanzadas de Ciberinteligencia

| Capacidad | Descripción | Beneficio |
|-----------|-------------|-----------|
| 🕵️ **Inteligencia de Amenazas** | Integración con fuentes de threat intelligence | Conocimiento proactivo de amenazas |
| 🔬 **Análisis Forense** | Investigación profunda de incidentes | Determinación de causa raíz |
| 📡 **Monitoreo en Tiempo Real** | Streaming de eventos y alertas | Respuesta inmediata |
| 🧪 **Simulación de Amenazas** | Pruebas de seguridad automatizadas | Validación de controles |
| 📈 **Trend Analysis** | Análisis de patrones históricos | Predicción de tendencias |

### 🏗️ Sistema Escalable de Punta

VANT-SIEM está diseñado como una **plataforma de punta** que escala vertical y horizontalmente:

- **Arquitectura de Microservicios**: Cada componente opera de manera independiente, permitiendo escalar únicamente los módulos que lo requieran
- **Procesamiento de Alto Volumen**: Capacidad de ingestar y procesar millones de eventos por segundo
- **Alta Disponibilidad**: Diseño tolerante a fallos con redundancia integrada
- **Balanceo de Carga**: Distribución inteligente del procesamiento entre nodos

---

## ⚖️ Cumplimiento Legal

### 📜 Resolución 105 - MINCOM (Ministerio de Comunicaciones)

VANT-SIEM ha sido diseñado para cumplir con los requisitos establecidos en la **Resolución 105** del **Ministerio de Comunicaciones (MINCOM)** de Cuba, que establece el marco legal normativo para la gestión de incidentes de seguridad Informatica en el país:

| Requisito | Cumplimiento VANT-SIEM |
|-----------|----------------------|
| 📝 **Registro de incidentes** | Bitácora de incidentes en tiempo real con trazabilidad completa |
| 👤 **Identificación de responsables** | Gestión de involucrados, responsables y áreas asignadas |
| ⏰ **Trazabilidad temporal** | Timestamps precisos, historial de estados y acciones |
| 📊 **Análisis y estadísticas** | Dashboard de incidentes, reportes y tendencias |
| 🔒 **Confidencialidad** | Control de acceso granular, autenticación LDAP |
| 📋 **Documentación** | Reportes formales, evidencia auditable |
| 🔄 **Ciclo de vida del incidente** | Workflow completo: detección → análisis → contención → resolución |
| 📑 **Notificación de incidentes** | Sistema de alertas y notificaciones a partes interesadas |
| 🏢 **Coordinación institucional** | workflow multi-nivel con escalamiento |

> 📢 **Nota**: La Resolución 105 del MINCOM establece las normas para la gestión de incidentes de seguridad Informatica en las organizaciones cubanas, incluyendo requisitos de reporte, tiempos de respuesta y procedimientos de coordinación.

---

## 🏗️ Arquitectura Modular Basada en Microservicios

VANT-SIEM adopta una **arquitectura desacoplada** basada en microservicios, separando la operación SIEM de la ingesta de alto volumen:

```
┌─────────────────────────────────────────────────────────────────┐
│                         VANT-SIEM                                │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │   CORE       │  │  VANT_SIEM   │  │      EVENT_M         │ │
│  │  (Orquestación)│ │  (Núcleo)    │  │  (Gestión Incidentes) │ │
│  └──────────────┘  └──────────────┘  └──────────────────────┘ │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │     IRIS     │  │  opensearch  │  │    opensearch_ui     │ │
│  │ (IA/Automát.) │ │  (Ingesta)   │  │   (Visualización)    │ │
│  └──────────────┘  └──────────────┘  └──────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### 📦 Módulos del Sistema

| Módulo | Descripción | Tecnologías |
|--------|-------------|-------------|
| 🏗️ **CORE** | Configuración y orquestación Django | Django, Python |
| ⚙️ **VANT_SIEM** | Núcleo SIEM: autenticación, notificaciones, dashboard principal | Django, Bootstrap 5 |
| 📋 **EVENT_M** | Gestión de incidentes, reportes,bitácora y seguimiento | Django, PostgreSQL |
| 🤖 **IRIS** | Analítica asistida por IA y automatización SOAR | scikit-learn, NumPy |
| 🌐 **opensearch** | Microservicio de ingesta de logs y agentes multi-fuente | Python, OpenSearch |
| 📊 **opensearch_ui** | Dashboard de logs y Discovery avanzado | Bootstrap, Chart.js |

---

## 🔐 SIEM - Security Information & Event Management

### 📊 Capacidades Principales

- **📥 Centralización de Eventos**: Recolección de eventos de múltiples fuentes (Snort, Suricata, Windows Event Logs, Samba AD, PostgreSQL)
- **🔍 Correlación de Eventos**: Análisis avanzado para identificar patrones de ataque
- **🚨 Alertas en Tiempo Real**: Notificaciones inmediatas ante eventos sospechosos
- **📈 Priorización por Severidad**: Clasificación automática de eventos por nivel de riesgo
- **🔎 Investigación Forense**: Búsqueda avanzada y análisis de comportamiento
- **📝 Auditoría Granular**: Registro detallado de todas las acciones y accesos

---

## 📝 Bitácora de Incidentes en Tiempo Real

VANT-SIEM proporciona una **bitácora completa** de incidentes con:

- 🕐 **Tiempo Real**: Registro inmediato de eventos y incidentes
- 📋 **Gestión Integral**: Creación, seguimiento y resolución de incidentes
- 👥 **Asignación de Responsables**: Control de quienes atienden cada incidente
- 📊 **Métricas y KPIs**: Indicadores de rendimiento del proceso de gestión
- 🔄 **Historial de Estados**: Trazabilidad completa del ciclo de vida
- 📑 **Reportes Formalizados**: Generación de informes cumpliendo normativas

---

## 🔍 Análisis de Logs y Observabilidad

### 🌐 Pipeline de OpenSearch

```
Fuentes de Datos → Agente → Servicio de Ingesta → OpenSearch → Dashboard
     (Snort,                                               │
      Suricata,                                            │
      Windows,                                             │
      AD, ...)                                             │
                                                            ↓
                                              ┌────────────────────┐
                                              │   opensearch_ui    │
                                              │  - Dashboards      │
                                              │  - Discovery       │
                                              │  - Visualizaciones │
                                              └────────────────────┘
```

### 📊 Dashboards Disponibles

| Dashboard | Ruta | Descripción |
|-----------|------|-------------|
| 🏠 **Principal** | `/opensearch/` | Vista general de eventos |
| 🛡️ **Snort IDS V2** | `/opensearch/snort/v2/` | Alertas IDS con timeline |
| 🔎 **Discovery** | `/opensearch/discover/` | Exploración avanzada de logs |

### 🎨 Constructor de Visualizaciones

- **📈 Gráficos**: Line, Bar, Area, Pie/Donut, Table, Metric
- **⚙️ Métricas**: Count, Average, Sum, Min, Max, Cardinality, Percentiles
- **🪣 Buckets**: Date Histogram, Terms, Filters
- **✨ Personalización**: Colores, leyendas, animaciones, etiquetas

---

## 🔐 Autenticación y Seguridad

### 🏢 Integración LDAP/Active Directory

VANT-SIEM soporta **autenticación centralizada** mediante LDAP:

- 🔒 **SSL/TLS** o StartTLS
- 👤 **Bind DN** opcional
- 🔍 **Búsqueda de usuarios** con placeholder `{username}`
- 📝 **Mapeo de atributos**: usuario, nombre, apellido, email
- ➕ **Auto-creación** de usuarios en el sistema

---

## 🤖 Inteligencia Artificial y Machine Learning

El módulo **IRIS** integra capacidades de IA para:

- 📊 **Análisis de comportamiento** y detección de anomalías
- 🔮 **Predicción de riesgos** y tendencias
- 🎯 **Clasificación automática** de incidentes
- 📈 **Optimización operativa** mediante modelos predictivos

---

## 🚀 Inicio Rápido

### Prerequisites

- Python 3.12+
- PostgreSQL 14+
- OpenSearch 2.x

### Instalación

```bash
# 1. Crear entorno virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
# Windows: venv\Scripts\activate

# 2. Instalar dependencias
pip install -r requirements.txt

# 3. Configurar base de datos en CORE/settings.py

# 4. Ejecutar migraciones
python manage.py migrate

# 5. Iniciar servidor
python manage.py runserver 0.0.0.0:8000
```

### Servicio OpenSearch (Windows)

```powershell
powershell -ExecutionPolicy Bypass -File .\opensearch\service\install_windows_service.ps1
```

### Agente OpenSearch (Windows)

```powershell
powershell -ExecutionPolicy Bypass -File .\dist\opensearch-agent-installer\package\Install-OpenSearchAgent.ps1 -RunNow
```

---

## 📚 Documentación

| Documento | Descripción |
|-----------|-------------|
| 📖 `docs/README.md` | Documentación general |
| 🏗️ `docs/ARCHITECTURE.md` | Arquitectura del sistema |
| 📦 `docs/INSTALLATION.md` | Guía de instalación |
| 📋 `docs/CHANGELOG.md` | Historial de cambios |
| 🔍 `docs/OPENSEARCH_FEATURE.md` | Características de OpenSearch |
| 🌐 `opensearch/README.md` | Documentación del agente |
| 📊 `opensearch_ui/README.md` | Documentación del UI |

---

## 🛠️ Tecnologías Utilizadas

<p align="left">

![Django](https://img.shields.io/badge/Django-5.x-green)
![Python](https://img.shields.io/badge/Python-3.12-blue)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-14+-blue)
![OpenSearch](https://img.shields.io/badge/OpenSearch-2.x-orange)
![Bootstrap](https://img.shields.io/badge/Bootstrap-5-purple)
![Chart.js](https://img.shields.io/badge/Chart.js-yellow)
![scikit-learn](https://img.shields.io/badge/scikit--learn-blue)

</p>

---

## 📄 Licencia

MIT License - © 2025 VANT-SIEM - Developed by **LLVT**

---

<div align="center">

**🛡️ VANT-SIEM** - *Vigilance And Neutralization of Threats*

*Plataforma integral de ciberseguridad para la gestión de incidentes en tiempo real*

*Integrando Inteligencia Artificial, Machine Learning y Ciberinteligencia de última generación*

</div>
