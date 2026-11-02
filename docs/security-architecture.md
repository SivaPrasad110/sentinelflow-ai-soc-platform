# SentinelFlow — Security Architecture

> **Document scope:** All Phase 1–7 security controls  
> **Last updated:** Phase 7 (Production Readiness)

---

## 1. Authentication Engine

### Password Hashing (Argon2id)
- Passwords are **never stored in plaintext**
- Algorithm: **Argon2id** — RFC 9106 recommendation; winner of the Password Hashing Competition
- Parameters:
  - Memory cost: **64 MB** (65,536 KiB)
  - Time cost: **3 iterations**
  - Parallelism: **4 threads**
- These parameters satisfy OWASP's minimum Argon2id recommendation

### Short-Lived Access Tokens
- Protocol: JSON Web Tokens (JWT), signed with HMAC-SHA256 (`HS256`)
- Expiration: **15 minutes**
- Claims:
  - `sub`: User UUID
  - `email`: User email address
  - `organizationId`: Active organization partition UUID
- Tokens are sent as `Authorization: Bearer` header — never in query strings or cookies

### Refresh Session Management
- Refresh tokens: **40-byte cryptographically secure random values** (`crypto.randomBytes(40)`)
- Storage: **SHA-256 hash only** — the raw token is never written to the database
- Session table: `RefreshSession` stores `tokenHash`, `userId`, `userAgent`, `ipAddress`, `expiresAt`, `revokedAt`
- **Automatic rotation**: Every `/auth/refresh` exchange atomically revokes the current session and issues a new token pair — this prevents refresh token replay attacks
- **Revocation on logout**: On `POST /auth/logout`, all matching sessions are marked `revokedAt = NOW()` immediately
- **Expiry**: Refresh sessions expire after 7 days

---

## 2. Organization Multi-Tenancy (Zero-Trust)

### Architecture
- Every user belongs to one or more organizations via the `OrganizationMembership` table
- Each HTTP request carries an `x-organization-id` header (treated as a hint, never as proof)
- The `JwtStrategy.validate()` method runs on every authenticated request and:
  1. Looks up the user's actual memberships from PostgreSQL (not from JWT claims)
  2. Verifies the requested `organizationId` against the server-side membership list
  3. Rejects with `HTTP 403 Forbidden` if the user is not a member of the requested org
- **No trust in client-supplied org identifiers** — only the server-side DB record is authoritative

### IDOR Mitigation
All database queries for tenant-scoped resources include:
```typescript
where: {
  id: resourceId,
  organizationId: verifiedOrgIdFromJwtStrategy,
}
```
Cross-tenant lookups silently return `null` and are surfaced as `404 Not Found` — giving zero intelligence to unauthorized callers.

### Role-Based Access Control (RBAC)

| Role | Capabilities |
|---|---|
| **`VIEWER`** | Read-only: incidents, alerts, analytics, audit log, IOCs, feeds |
| **`ANALYST`** | All VIEWER + create/update incidents, ingest alerts, trigger n8n triage, manage IOCs/feeds/detection rules |
| **`ADMIN`** | All ANALYST + delete incidents, manage org settings, view all audit logs |

Enforced via:
- `@UseGuards(JwtAuthGuard, RolesGuard)` on all protected controllers
- `@Roles(Role.ANALYST, Role.ADMIN)` decorator checked by `RolesGuard`
- `ROLE_HIERARCHY: { VIEWER: 1, ANALYST: 2, ADMIN: 3 }` allows higher roles to satisfy lower requirements

---

## 3. Defense-in-Depth Controls

### HTTP Security Headers (Helmet — Phase 7)
Applied as the first middleware in the NestJS bootstrap:
| Header | Value | Effect |
|---|---|---|
| `Content-Security-Policy` | `default-src 'self'` + scoped exceptions | Blocks inline scripts, external resources |
| `X-Frame-Options` | `DENY` (via NGINX) | Prevents clickjacking |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type sniffing |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Controls referrer leakage |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | Enforces HTTPS (production only) |
| `Permissions-Policy` | Disables camera, microphone, geolocation | Minimal permissions surface |

### CORS (Cross-Origin Resource Sharing)
- HTTP CORS: exact whitelist from `CORS_ORIGIN` env var (comma-separated for multi-domain)
- WebSocket CORS: same `CORS_ORIGIN` env var — **no wildcard (`*`) is ever used**
- Both support localhost for development without disabling the whitelist mechanism

### Rate Limiting
- **Global**: 60 requests/minute per client IP (`@nestjs/throttler`)
- **Login endpoint**: 5 attempts/minute per client IP (`@Throttle({ default: { limit: 5, ttl: 60000 } })`)
- Defense against brute-force and credential stuffing attacks

### Request Validation
- `ValidationPipe` with `whitelist: true` strips undeclared properties
- `forbidNonWhitelisted: true` **rejects** requests containing undeclared fields (Phase 7 fix)
- `transform: true` auto-converts query/path parameters to declared types

### Cookie Security
- Refresh token cookies: `HttpOnly`, `SameSite=Lax`, `Path=/api/v1/auth`
- `Secure` flag enabled when `NODE_ENV=production`
- Cookie path restriction (`/api/v1/auth`) prevents the cookie from being sent to other endpoints

### Request Correlation IDs (Phase 7)
- `CorrelationIdMiddleware` reads `X-Request-Id` from request or generates a UUID v4
- ID attached to `req.correlationId` for structured log tracing
- ID echoed back in response `X-Request-Id` header for client-side correlation

---

## 4. Detection Engine Security (Phase 6)

### ReDoS Protection (Phase 7)
The REGEX operator in the detection rule evaluator guards against catastrophic backtracking:
1. **Length limit**: Patterns longer than 300 characters are rejected
2. **Nested quantifier detection**: Patterns matching `(x+)+`, `(x*)+`, `(x|x)*` are rejected before compilation
3. **Compile-time error catching**: Any remaining malformed patterns are caught in try/catch and return false

### Alert Storm Deduplication
Each security finding receives a SHA-256 fingerprint:
```
fingerprint = SHA256(organizationId + ruleId + alertSource + normalizedAlertTitle)
```
If a matching finding already exists in `NEW` or `ANALYZED` status, the duplicate alert increments an evidence counter instead of creating a new finding. This prevents noisy environments from overwhelming the finding queue.

### IOC Format Validation
Before ingesting any indicator from an external feed, the `IocService.validateIocFormat()` method validates:
- **IP**: Valid IPv4 octet range (0–255), rejects reserved ranges in defensive seeds
- **DOMAIN**: Valid hostname pattern with TLD, rejects bare hostnames
- **HASH_SHA256**: Exactly 64 hex characters
- **HASH_MD5**: Exactly 32 hex characters
- **URL**: Must begin with `http://` or `https://`
- **EMAIL**: Standard `user@domain.tld` format

---

## 5. External Service Security

### n8n Webhook Authentication
- All dispatched webhooks include an `x-n8n-secret` header with the `N8N_WEBHOOK_SECRET` value
- n8n Cloud verifies this header before executing the workflow
- The shared secret is stored in environment variables only — never in source code or logs
- Callback handler validates the `executionId` matches a known pending analysis

### Threat Feed Validation
- All feed data is fetched with a **10-second timeout** and abort controller
- Feed data is normalized and validated against the IOC format rules before ingestion
- If the feed is unreachable or returns invalid data, the system falls back to curated **defensive seed indicators** using RFC-reserved IP addresses (not real infrastructure)
- Feed fetch errors are logged and stored in `ThreatFeed.errorMessage` without crashing the server

---

## 6. Production Deployment Security

### HTTPS Enforcement
- In production, **all traffic must go through NGINX with TLS termination**
- HSTS header enforces HTTPS for 1 year with `preload` flag
- HTTP → HTTPS redirect at the NGINX level
- Certificates via Let's Encrypt (certbot) or managed provider

### Secret Management
| Secret | Generation Command | Storage |
|---|---|---|
| `JWT_SECRET` | `node -e "require('crypto').randomBytes(64).toString('base64url')"` | Env var / Vault |
| `N8N_WEBHOOK_SECRET` | Generate in n8n Cloud webhook settings | Env var |
| `DATABASE_URL` | Provided by managed DB provider | Env var |

**Rules:**
- Secrets are **never committed to version control**
- `.env` and `.env.production` are in `.gitignore`
- `.env.example` and `.env.production.example` contain only placeholder values
- For production, use a secrets manager (AWS Secrets Manager, HashiCorp Vault, Railway Variables)

### Demo / Seed Account Management
- Seeded accounts (`admin@sentinelflow.local`, etc.) are **local development only**
- The `seed.ts` uses `upsert` — re-running is idempotent and does not duplicate records
- **Before any production deployment**, change or delete all seeded accounts

---

## 7. Security Controls Checklist

| Control | Status | Phase |
|---|---|---|
| Argon2id password hashing | ✅ | Phase 2 |
| JWT access tokens (15m expiry) | ✅ | Phase 2 |
| Refresh token rotation | ✅ | Phase 2 |
| Refresh token hash-only storage | ✅ | Phase 2 |
| Org membership server-side verification | ✅ | Phase 2 |
| IDOR mitigation (org-scoped queries) | ✅ | Phase 2 |
| RBAC (VIEWER / ANALYST / ADMIN) | ✅ | Phase 2 |
| Rate limiting (global + login) | ✅ | Phase 2 |
| HttpOnly refresh token cookies | ✅ | Phase 2 |
| WebSocket JWT authentication | ✅ | Phase 5 |
| WebSocket org-room isolation | ✅ | Phase 5 |
| WebSocket org-switch verification | ✅ | Phase 5 |
| IOC format validation | ✅ | Phase 6 |
| Alert storm deduplication (fingerprint) | ✅ | Phase 6 |
| Feed timeout + error handling | ✅ | Phase 6 |
| Helmet HTTP security headers | ✅ | Phase 7 |
| CORS exact whitelist (no wildcard) | ✅ | Phase 7 |
| WebSocket CORS exact whitelist | ✅ | Phase 7 |
| JWT secret variable normalization | ✅ | Phase 7 |
| `forbidNonWhitelisted: true` | ✅ | Phase 7 |
| ReDoS protection in detection engine | ✅ | Phase 7 |
| Request correlation IDs | ✅ | Phase 7 |
| Production env template (no real secrets) | ✅ | Phase 7 |
