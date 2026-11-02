# SentinelFlow — Demo Guide

> **Purpose:** Safe walkthrough for portfolio reviewers and hiring managers  
> **Estimated time:** 15–20 minutes  
> **Requirements:** Local development stack running (see [deployment.md](deployment.md))

---

## ⚠️ Safety Rules

1. **Never share production credentials** in any demo recording or screenshot
2. **Use only the seeded demo accounts** — never a real user's credentials
3. **Do not demo with a live n8n workflow** receiving real incident traffic
4. **Redact any `DATABASE_URL` or `JWT_SECRET` values** before screen-sharing

---

## Setup: Start the Demo Environment

```bash
# 1. Start PostgreSQL
docker compose up -d

# 2. Apply migrations and seed demo data
cd apps/api && npx prisma migrate dev --name init && npx prisma db seed && cd ../..

# 3. Start API (Terminal 1)
npm run start:dev --workspace=apps/api

# 4. Start Frontend (Terminal 2)
npm run dev --workspace=apps/web

# 5. Open browser
open http://localhost:5173
```

---

## Demo Account Credentials

| Account | Email | Password | Role | Use Case |
|---|---|---|---|---|
| SOC Administrator | `admin@sentinelflow.local` | `Admin123!` | ADMIN | Full demo walk-through |
| SOC Analyst | `analyst@sentinelflow.local` | `Analyst123!` | ANALYST | Triage demonstration |
| Read-Only Viewer | `viewer@sentinelflow.local` | `Viewer123!` | VIEWER | RBAC restriction demo |

---

## Walk-Through Script

### Step 1 — Authentication (2 min)
1. Open `http://localhost:5173`
2. Log in as **admin@sentinelflow.local** / `Admin123!`
3. **Highlight:** The login endpoint is rate-limited to 5 attempts/minute; tokens expire in 15 minutes; refresh tokens rotate on every use

### Step 2 — SOC Dashboard Overview (2 min)
1. Show the **4 KPI cards**: Scoped Incidents, Active Alerts, Active Role, Active Boundary
2. **Highlight:** The "Active Boundary" card shows which organization's data you're viewing — all data is strictly scoped to this organization

### Step 3 — Ingest a Security Alert (3 min)
1. Click **Raw Alerts Stream** tab
2. Click **Ingest Alert** → fill in:
   - Title: `Suspicious PowerShell Execution Detected`
   - Source: `EDR Agent`
   - Severity: `HIGH`
   - Description: `Encoded PowerShell with -ExecutionPolicy Bypass and -EncodedCommand flags`
3. Submit — the alert appears in the stream instantly (no page refresh — WebSocket push)
4. **Highlight:** The alert is simultaneously evaluated against detection rules

### Step 4 — Detection Engine (3 min)
1. Click **Detections & MITRE** tab
2. Show the **pre-seeded detection rules** (PowerShell, LSASS, Cobalt Strike, Ransomware)
3. Click on a detection rule — show the criteria, MITRE ATT&CK mapping, trigger count
4. Show the **Security Findings** list — the PowerShell alert just generated a finding
5. **Highlight:** The finding has a calculated risk score, MITRE technique ID (T1059.001), and a deterministic SHA-256 fingerprint that prevents duplicate alert storms

### Step 5 — Promote Finding to Incident (2 min)
1. On a finding, click **Promote to Incident**
2. Switch to **Incidents Queue** tab — the new incident appears
3. **Highlight:** The incident was automatically enriched with mitigation steps and MITRE ATT&CK context from the detection rule

### Step 6 — n8n AI Triage (3 min)
1. Select the new incident
2. Click **Trigger n8n Triage**
3. Show the n8n Cloud integration in the **n8n Playbook Automation** tab
4. **Highlight:** SentinelFlow sends the incident to n8n Cloud via a webhook with a shared secret. n8n runs an AI analysis workflow and POSTs the structured result back. The analysis appears on the incident timeline in real-time via WebSocket.

### Step 7 — Threat Intelligence (2 min)
1. Click **Threat Intel & Feeds** tab
2. Show the three default feeds (URLhaus, ThreatFox, Feodo Tracker)
3. Click **Sync** on one — shows the defensive seed indicators loading if the external feed is unavailable
4. Show the IOC list with type, severity, MITRE tactics, and threat score

### Step 8 — Audit Log (1 min)
1. Click **Security Audit Log** tab
2. Show the chronological log of all actions performed during the demo
3. **Highlight:** Every action is tied to organizationId, userId, and IP address

### Step 9 — Role-Based Access Control Demo (2 min)
1. Log out
2. Log in as **viewer@sentinelflow.local** / `Viewer123!`
3. Try to create an incident — the button is absent/disabled
4. Try to ingest an alert — rejected
5. **Highlight:** VIEWER role is read-only; the role is enforced server-side in the RolesGuard, not just hidden on the frontend

---

## Common Demo Questions & Answers

**Q: Is this multi-tenant?**  
A: Yes. Each organization is a fully isolated tenant. Users can belong to multiple organizations and switch between them. All database queries are scoped by `organizationId`.

**Q: How are secrets stored?**  
A: Passwords are hashed with Argon2id (64 MB memory cost, 3 iterations). Refresh tokens are never stored — only their SHA-256 hash is recorded. JWT access tokens are short-lived (15 minutes).

**Q: What does n8n do?**  
A: n8n is a low-code workflow automation platform. SentinelFlow uses it as a pluggable AI triage engine — you can connect any LLM, SOAR tool, or notification system by editing the n8n workflow without changing the SentinelFlow codebase.

**Q: What happens if a threat feed goes offline?**  
A: The threat intel service falls back to a curated set of defensive seed indicators (realistic IOCs from RFC-reserved address space) so the platform remains functional in air-gapped or network-restricted environments.

**Q: How does the detection engine prevent alert storms?**  
A: Each finding gets a SHA-256 fingerprint computed from `orgId + ruleId + alertSource + alertTitle`. If a matching finding already exists in `NEW` or `ANALYZED` status, the duplicate alert increments an evidence counter instead of creating a new finding.
