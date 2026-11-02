# SentinelFlow — API Reference

> **Base URL (local):** `http://localhost:3000/api/v1`  
> **Base URL (production):** `https://api.yourdomain.com/api/v1`  
> **Interactive Swagger UI:** `/api/docs`  
> **Authentication:** Bearer JWT (access token from `/auth/login`)

---

## Authentication

### POST /auth/register
Register a new user and create their organization.

**Request:**
```json
{
  "email": "admin@example.com",
  "password": "SecurePassword123!",
  "name": "Alex Johnson",
  "organizationName": "Acme Security"
}
```

**Response 201:**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiJ9...",
  "user": {
    "id": "uuid",
    "email": "admin@example.com",
    "name": "Alex Johnson",
    "activeOrganizationId": "org-uuid",
    "activeRole": "ADMIN",
    "memberships": [{ "organizationId": "org-uuid", "organizationName": "Acme Security", "role": "ADMIN" }]
  }
}
```

Sets `refresh_token` HttpOnly cookie (7-day expiry, `SameSite=Lax`).

---

### POST /auth/login
Authenticate with email and password. Rate limited: **5 attempts/minute**.

**Request:**
```json
{
  "email": "admin@example.com",
  "password": "SecurePassword123!",
  "organizationIdHint": "optional-org-uuid"
}
```

**Response 200:** Same shape as `/auth/register`  
**Response 401:** Invalid credentials  
**Response 429:** Rate limit exceeded

---

### POST /auth/refresh
Exchange refresh token (from cookie or body) for a new token pair.

**Response 200:**
```json
{ "accessToken": "eyJhbGciOiJIUzI1NiJ9..." }
```

New `refresh_token` cookie is set automatically.

---

### POST /auth/logout
Revoke active refresh session.

**Response 200:** `{ "success": true }`  
Clears the `refresh_token` cookie.

---

### GET /auth/me
Get the authenticated user's profile and org memberships.

**Headers:** `Authorization: Bearer ACCESS_TOKEN`  
**Headers (optional):** `x-organization-id: ORG_UUID`

**Response 200:**
```json
{
  "id": "user-uuid",
  "email": "admin@example.com",
  "name": "Alex Johnson",
  "activeOrganizationId": "org-uuid",
  "activeRole": "ADMIN",
  "memberships": [...]
}
```

---

## Health

### GET /health
Check API and integrated service status. No authentication required.

**Response 200:**
```json
{
  "status": "ok",
  "timestamp": "2026-11-01T00:00:00.000Z",
  "uptimeSeconds": 3600,
  "environment": "production",
  "version": "0.1.0",
  "services": {
    "api": "healthy",
    "database": "connected",
    "n8n": "reachable"
  }
}
```

**Response 200 (degraded):** `"status": "degraded"` with `"database": "disconnected"`.

---

## Incidents

> **Auth required:** All endpoints. Org scope from `x-organization-id` header.

### GET /incidents
List all incidents for the authenticated user's organization.

**Query params:** `?status=NEW&severity=CRITICAL`

**Response 200:** Array of Incident objects

### POST /incidents
Create a new incident. **Requires ANALYST or ADMIN role.**

**Request:**
```json
{
  "title": "Ransomware Activity Detected",
  "description": "Multiple hosts affected by file encryption",
  "severity": "CRITICAL",
  "status": "NEW",
  "sourceAlertIds": ["alert-uuid"],
  "mitigationSteps": ["Isolate affected hosts", "Preserve memory images"]
}
```

### GET /incidents/:id
Get a single incident with timeline events and AI analyses.

### PATCH /incidents/:id
Update incident status, severity, or mitigation steps. **Requires ANALYST or ADMIN.**

### DELETE /incidents/:id
Delete an incident. **Requires ADMIN role.**

### POST /incidents/:id/analyze
Trigger n8n AI triage workflow for an incident. **Requires ANALYST or ADMIN.**

**Response 202:** `{ "message": "Triage workflow dispatched", "analysisId": "uuid" }`

---

## Alerts

### GET /alerts
List security alerts for the authenticated organization.

**Query params:** `?severity=HIGH&limit=50`

### POST /alerts
Ingest a new security alert. **Requires ANALYST or ADMIN.**

**Request:**
```json
{
  "title": "Suspicious PowerShell Execution",
  "description": "Encoded command with -ExecutionPolicy Bypass",
  "severity": "HIGH",
  "source": "EDR Agent",
  "rawPayload": { "hostname": "WORKSTATION-01", "pid": 4821 }
}
```

On ingestion, the alert is **automatically evaluated** against all enabled detection rules. Matching findings are created asynchronously.

---

## Detection Engine

### GET /detection/rules
List all detection rules for the organization.

### POST /detection/rules
Create a detection rule. **Requires ANALYST or ADMIN.**

**Request:**
```json
{
  "name": "Mimikatz LSASS Access",
  "description": "Detects credential dumping via LSASS",
  "severity": "CRITICAL",
  "ruleType": "PATTERN",
  "criteria": [
    { "field": "description", "operator": "CONTAINS", "value": "lsass" },
    { "field": "source", "operator": "EQUALS", "value": "EDR" }
  ],
  "mitreTechniqueId": "T1003.001"
}
```

**Supported operators:** `EQUALS`, `CONTAINS`, `STARTS_WITH`, `REGEX`, `IN`, `GREATER_THAN`  
**Supported ruleTypes:** `PATTERN`, `IOC_MATCH`, `THRESHOLD`

### GET /detection/findings
List security findings with optional filters.

**Query params:** `?status=NEW&severity=HIGH`

### POST /detection/findings/:id/promote
Escalate a finding to a full incident. **Requires ANALYST or ADMIN.**

### POST /detection/findings/:id/dismiss
Dismiss a finding with an optional reason. **Requires ANALYST or ADMIN.**

---

## Threat Intelligence

### GET /threat-intel/feeds
List all threat intelligence feeds for the organization.

### POST /threat-intel/feeds
Register a new threat feed. **Requires ADMIN.**

**Request:**
```json
{
  "name": "Custom Blocklist",
  "feedUrl": "https://your-blocklist.example.com/iocs.json",
  "feedType": "CUSTOM",
  "format": "JSON",
  "enabled": true
}
```

### POST /threat-intel/feeds/:id/sync
Trigger a manual feed synchronization. **Requires ANALYST or ADMIN.**

**Response 200:**
```json
{
  "feedId": "uuid",
  "feedName": "Abuse.ch URLhaus",
  "status": "SUCCESS",
  "indicatorsImported": 12,
  "indicatorsUpdated": 3,
  "durationMs": 2340
}
```

### GET /threat-intel/stats
Get threat intelligence statistics.

**Response 200:**
```json
{
  "totalIocs": 45,
  "activeIocs": 42,
  "feedCount": 3,
  "iocsByType": { "IP": 18, "DOMAIN": 12, "URL": 8, "HASH_SHA256": 7, "HASH_MD5": 0, "EMAIL": 0 },
  "iocsBySeverity": { "CRITICAL": 15, "HIGH": 20, "MEDIUM": 8, "LOW": 2 },
  "totalFindings": 31,
  "unresolvedFindings": 7,
  "mitreCoverageCount": 11
}
```

---

## IOCs

### GET /ioc
List IOCs for the organization.

### POST /ioc
Create a manual IOC. **Requires ANALYST or ADMIN.**

```json
{
  "type": "IP",
  "value": "203.0.113.88",
  "severity": "CRITICAL",
  "threatScore": 95,
  "description": "Known C2 server",
  "tags": ["cobalt-strike", "c2"],
  "mitreTactics": ["Command and Control"],
  "mitreTechniques": ["T1071.001"]
}
```

---

## Analytics

### GET /analytics
Get SOC analytics metrics including MTTA, MTTR, incident distribution, and severity breakdown.

**Response 200:**
```json
{
  "totalIncidents": 47,
  "openIncidents": 12,
  "resolvedIncidents": 35,
  "mttr": 14400,
  "mtta": 3600,
  "incidentsBySeverity": { "CRITICAL": 5, "HIGH": 18, "MEDIUM": 20, "LOW": 4 },
  "incidentsByStatus": { "NEW": 4, "TRIAGED": 3, "INVESTIGATING": 5, "RESOLVED": 35 },
  "alertsIngested": 203,
  "findingsGenerated": 31
}
```

---

## Audit Log

### GET /audit
Retrieve the organization's audit log. **Requires ANALYST or ADMIN.**

**Query params:** `?action=AUTH_LOGIN&limit=100&offset=0`

**Response 200:** Array of AuditLog objects with action, entityType, entityId, userId, ipAddress, createdAt.

---

## Error Response Format

All error responses follow:
```json
{
  "statusCode": 403,
  "message": "Insufficient permissions: role \"VIEWER\" does not satisfy required role(s): [ANALYST].",
  "error": "Forbidden"
}
```

Common status codes:
| Code | Meaning |
|---|---|
| 400 | Validation error (DTO field violation) |
| 401 | Missing or expired access token |
| 403 | Insufficient role or cross-tenant access attempt |
| 404 | Resource not found (intentional for cross-tenant IDOR protection) |
| 409 | Conflict (e.g., email already registered) |
| 429 | Rate limit exceeded |
| 500 | Internal server error |
