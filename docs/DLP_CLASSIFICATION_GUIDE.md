# DLP Classification Guide

## Objective

This guide defines how VANT-SIEM treats sensitive content inside the Aegis DLP service.

## Protected Classes

### Clasificado

Use for material that explicitly identifies itself as classified information or contains equivalent headers, labels or embedded markers.

### Secreto

Use for information with restricted circulation whose exposure would create a severe institutional or security impact.

### Seguridad del Estado

Use for content tied to sovereign operations, protected institutional procedures or state security context.

### Restringido

Use for operational data that should not be publicly distributed and requires controlled circulation.

## Detection Strategy

Aegis DLP evaluates:

- file names
- file paths
- document body content
- XML payloads inside Office documents
- file metadata attached to the incident payload

## Recommended Governance

- Maintain an approved vocabulary for protected information.
- Add custom rules for internal project names, codewords and operation identifiers.
- Review open incidents daily.
- Correlate DLP incidents with inventory timeline events and user activity.
- Preserve hashes and paths for forensic continuity.

## Custom Sovereign Rules

Beyond default classified labels, organizations should define their own sovereign or project-specific keywords using the Aegis DLP policy engine in Django admin.

Recommended examples:

- project codenames
- ministry or institutional labels
- controlled document headers
- internal classification banners
- export-control terminology

## Incident Lifecycle

1. The agent detects a match.
2. The incident is uploaded to the server.
3. A timeline event is created for the affected endpoint.
4. Analysts review actor, path, channel and file hash.
5. Governance teams update or refine policy rules when necessary.
