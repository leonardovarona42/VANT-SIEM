# Agent Microservices

## Overview

The VANT-SIEM agent now includes two embedded microservices designed for host visibility and information protection:

- `asset_audit`: asset inventory, historical audit trail, hardware and software visibility.
- `aegis_dlp`: data leak prevention for classified, secret, restricted and sovereign-sensitive content.

These modules run inside the same agent runtime and report to the Django control plane through authenticated agent APIs.

## Asset Audit

### Purpose

`asset_audit` builds a historical record of what existed on a monitored workstation or server.

### Collected data

- BIOS, board, CPU and system identifiers.
- Disk and USB device identities.
- MAC addresses, IPv4 identities and interfaces.
- Installed software and observed versions.
- Logged users and session observations.
- Timeline events for newly observed hardware, software, users and network identities.

### Server-side persistence

Inventory and audit data are stored through the `inventory` app:

- `AgentInventorySnapshot`
- `AgentHardwareComponent`
- `AgentSoftwareRecord`
- `AgentNetworkIdentity`
- `AgentTimelineEvent`

## Aegis DLP

### Purpose

`aegis_dlp` protects information by scanning monitored files for regulated or sovereign-sensitive content.

### Default detections

The default Aegis policy detects content labeled as:

- `informacion clasificada`
- `secreto`
- `seguridad del estado`
- `restringido`

### Sources inspected

- File name and path.
- File content.
- Office Open XML content (`.docx`, `.xlsx`, `.pptx`).
- File metadata recorded in incidents.

### Incident model

Detected findings generate:

- `AegisDlpIncident`
- DLP timeline events in `AgentTimelineEvent`
- EVENT_M reports and incidents when the operator escalates from the OSIC queue

Each incident includes:

- actor
- path
- hash
- channel
- classification
- severity
- timestamps

### OSIC-Threads workflow

The Aegis console now exposes DLP findings as `OSIC-Threads` with a direct operational flow:

1. The agent detects a document or file artifact and creates an `AegisDlpIncident`.
2. The dashboard auto-refreshes the queue and lets the analyst preview local content when available, or inspect structured evidence when it is not.
3. `Reportar` creates:
   - an `EVENT_M.Reporte` in state `Atendido`
   - an `EVENT_M.Incidente` in state `abierto`
   - a JSON evidence artifact attached to the incident
4. The originating `AegisDlpIncident` is updated with:
   - reporting user
   - reporting timestamp
   - linked `Reporte`
   - linked `Incidente`
   - status `contained`

### Evidence bundle

When the original file is not physically reachable from the Django server, VANT-SIEM still preserves actionable evidence by serializing:

- host name, agent identifier and observed IP
- actor / file owner
- path and file hash
- classification and severity
- policy and rule
- matched keywords
- metadata captured by the endpoint agent

## Windows Server and Active Directory

For Windows Server deployments, the GUI installer now supports an AD-oriented event profile.

Recommended channels:

- `Security`
- `System`
- `Application`
- `Directory Service`
- `DNS Server`
- `DFS Replication`
- `Active Directory Web Services`

These channels are written to `collectors.windows_eventlog.channels` in the generated `config.yaml`.

## Management Views

The Django dashboard now includes dedicated sections for:

- Inventory and audit operations.
- Aegis DLP monitoring and policy governance.

Primary UI routes:

- `/siem/dashboard/devices/management/`
- `/siem/dashboard/devices/inventory/`
- `/siem/dashboard/devices/dlp/`

## Operational Notes

- The Windows installer bundles these modules for offline deployment.
- Linux packaging scripts are aligned with the same microservice structure.
- DLP policies can be tuned from the Django admin under `inventory`.
- Daily OSIC triage no longer depends on the Django admin; operators can preview and escalate directly from the dashboard.
