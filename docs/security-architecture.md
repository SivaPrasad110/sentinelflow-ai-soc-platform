# SentinelFlow Phase 2: Security, Authentication & Multi-Tenant RBAC Architecture

This document outlines the production security architecture, authentication flow, authorization controls, and secret management guidelines for the SentinelFlow AI SOC Platform.

---

## 1. Authentication Engine

### Password Hashing (Argon2id)
- Passwords are never stored in plaintext.
- Hashing algorithm: **Argon2id** (the winner of the Password Hashing Competition and RFC 9106 recommendation).
- Memory cost: 64 MB (65,536 KiB), Time cost: 3 iterations, Parallelism: 4 threads.

### Short-Lived Access Tokens
- Protocol: JSON Web Tokens (JWT) signed with HMAC-SHA256 (`HS256`) or RS256 in clustered environments.
- Expiration: **15 minutes**.
- Claims:
  - `sub`: User UUID
  - `email`: User email
  - `organizationId`: Active organization partition UUID

### Secure Refresh Session & Token Rotation
- Refresh tokens are 40-byte cryptographically secure random values (`crypto.randomBytes(40)`).
- Raw refresh tokens are **never stored** in the database; only a SHA-256 hash is recorded in `RefreshSession`.
- **Automatic Rotation**: On every refresh token exchange (`POST /auth/refresh`), the current session is immediately marked revoked (`revokedAt = now()`), and a brand-new token pair is issued.
- **Revocation / Logout**: On logout, matching refresh sessions are marked revoked immediately.

---

## 2. Organization Multi-Tenancy & Authorization

### Zero-Trust Header Verification
- Client-supplied `x-organization-id` or `x-tenant-id` headers are treated solely as **selection hints**, never as proof of authorization.
- On every request, the `JwtStrategy` resolves the authenticated user's organization memberships directly from PostgreSQL (`OrganizationMembership`).
- If a user specifies an organization header for which they lack membership, the request is immediately rejected with `HTTP 403 Forbidden`.

### Role-Based Access Control (RBAC)
Roles are scoped per organization membership:
| Role | Permissions & Endpoint Access |
| :--- | :--- |
| **`VIEWER`** | Read-only access to incidents and telemetry alerts. Cannot create incidents, ingest alerts, modify mitigations, or delete resources. |
| **`ANALYST`** | Full triage access: view alerts/incidents, create new incidents, update incident severity, edit AI triage mitigations, and ingest telemetry. |
| **`ADMIN`** | Complete operational governance: all Analyst capabilities plus incident deletion, member role assignment, and organization settings. |

Enforced via NestJS `RolesGuard` and `@Roles(Role.ANALYST, Role.ADMIN)` decorators.

---

## 3. Defense-in-Depth Protections

### Rate Limiting (Anti-Brute Force)
- Configured via `@nestjs/throttler`:
  - Global API: 60 requests/minute per client IP.
  - Login endpoint (`POST /auth/login`): **5 attempts/minute** per client IP.

### Insecure Direct Object Reference (IDOR) Mitigation
- All database queries for incidents, alerts, IOCs, and workflow execution logs include:
  ```typescript
  where: {
    id: resourceId,
    OR: [{ organizationId: userAuthorizedOrgId }, { tenantId: userAuthorizedOrgId }]
  }
  ```
- Cross-tenant lookups fail with `404 Not Found`, giving zero intelligence to unauthorized callers.

### Secure Cookies & CORS
- Refresh token cookies: `HttpOnly`, `SameSite=Lax`, `Path=/api/v1/auth`, `Secure` (in production).
- CORS: Strict origin whitelisting (`CORS_ORIGIN`), credentials enabled (`credentials: true`).

---

## 4. Production Deployment & Secret Management

1. **HTTPS Enforcement**:
   - In production, SentinelFlow **must** be deployed behind an SSL/TLS reverse proxy (NGINX, Cloudflare, AWS ALB) with HSTS headers.
   - Set `NODE_ENV=production` so cookies enforce the `Secure` flag.

2. **Secret Management**:
   - `JWT_SECRET`: Must be generated using a cryptographically secure random source (min. 256-bit entropy).
     ```bash
     node -e "console.log(require('crypto').randomBytes(64).toString('base64'))"
     ```
   - Store in AWS Secrets Manager, HashiCorp Vault, or Azure Key Vault. **Never** check `.env` into version control.
   - Seed accounts (`admin@sentinelflow.local`, etc.) are intended **strictly for local development and testing**. Change or delete them in production deployments.
