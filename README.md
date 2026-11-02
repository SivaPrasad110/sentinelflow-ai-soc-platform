# SentinelFlow

**AI-Augmented Security Operations Platform**

> A production-grade, multi-tenant SOC platform built with NestJS, React, PostgreSQL, and n8n Cloud — featuring real-time threat detection, AI incident triage, MITRE ATT&CK mapping, and cryptographically secure multi-org isolation.

[![Node.js](https://img.shields.io/badge/Node.js-20_LTS-339933?logo=node.js&logoColor=white)](https://nodejs.org)
[![NestJS](https://img.shields.io/badge/NestJS-10-E0234E?logo=nestjs&logoColor=white)](https://nestjs.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)](https://react.dev)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)](https://postgresql.org)
[![Prisma](https://img.shields.io/badge/Prisma-5-2D3748?logo=prisma&logoColor=white)](https://prisma.io)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white)](https://typescriptlang.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](https://docker.com)
[![Tests](https://img.shields.io/badge/Tests-119%20passing-22C55E?logo=jest&logoColor=white)](./apps/api/src)

---

## What is SentinelFlow?

SentinelFlow is a full-stack Security Operations Center (SOC) platform that demonstrates production-level engineering across security, multi-tenancy, real-time systems, and AI automation.

It is designed as a **portfolio project** that showcases:

- **Production security engineering** — Argon2id password hashing, JWT rotation, ReDoS protection, CORS hardening, HTTP security headers, and zero-trust tenant isolation
- **Real-time architecture** — WebSocket-powered live incident/alert feeds with JWT-authenticated org-room isolation
- **AI automation pipeline** — n8n Cloud integration for LLM-powered incident triage with structured evidence extraction
- **Detection engineering** — Rule-based alert evaluation engine with MITRE ATT&CK mapping, risk scoring, and alert storm deduplication
- **Threat intelligence** — Automated feed ingestion from Abuse.ch and Feodo Tracker with IOC normalization and defensive fallback

---

## Feature Highlights

### 🔐 Security-First Architecture
- **Argon2id** password hashing (64 MB memory, 3 iterations, 4 threads)
- **Short-lived JWT access tokens** (15 minutes) + cryptographically secure refresh sessions
- **Automatic refresh token rotation** — old session revoked immediately on each exchange
- **Multi-tenant isolation** — every database query is scoped by verified `organizationId`
- **HTTP security headers** via Helmet (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- **Rate limiting** — 60 req/min global, 5 req/min on login endpoints
- **ReDoS protection** in detection regex evaluation

### 📡 Real-Time SOC Dashboard
- Live **incident queue** with severity-weighted ordering
- **Alert stream** with automatic detection evaluation on ingestion
- **WebSocket push** — no polling; updates delivered instantly to the correct org room
- **Org-switch** support — users can switch between organizations without re-login

### 🧠 AI Incident Triage (n8n Cloud)
- One-click incident dispatch to an n8n Cloud automation workflow
- Workflow performs AI analysis and POSTs structured results back
- Analysis includes: severity assessment, impact prediction, recommended actions, confidence score
- Full execution timeline stored per incident

### 🎯 Detection Engine
- Rule-based alert evaluation (PATTERN, IOC_MATCH, THRESHOLD rule types)
- MITRE ATT&CK technique and tactic classification for every finding
- Explainable **risk scoring** with per-factor breakdown
- **SHA-256 fingerprinting** prevents duplicate findings from alert storms
- Finding escalation to incidents with one click

### 📊 Threat Intelligence
- Live feed sync from Abuse.ch URLhaus, ThreatFox, and Feodo Tracker
- IOC normalization with format validation for IP, DOMAIN, HASH_SHA256, HASH_MD5, URL, EMAIL
- Graceful **offline fallback** to curated defensive seed indicators
- MITRE technique tagging per IOC

### 📋 SOC Analytics
- **MTTA** (Mean Time to Acknowledge) and **MTTR** (Mean Time to Resolve) metrics
- Incident severity distribution and status funnel
- Alert volume trends

---

## Tech Stack

| Layer | Technology |
|---|---|
| **API** | NestJS 10 · Passport-JWT · class-validator · Swagger/OpenAPI |
| **Frontend** | React 18 · Vite 5 · TypeScript · TailwindCSS · Lucide icons |
| **Database** | PostgreSQL 16 · Prisma 5 ORM |
| **Real-Time** | Socket.IO 4 (WebSocket + polling fallback) |
| **Auth** | Argon2id · JWT (HS256) · HttpOnly cookies |
| **Security** | Helmet · @nestjs/throttler · CORS whitelist |
| **Automation** | n8n Cloud (webhook-based) |
| **Infrastructure** | Docker · Docker Compose · NGINX |
| **Testing** | Jest · ts-jest · Vitest |
| **Shared Types** | `@sentinelflow/shared` monorepo package |

---

## Architecture

```
Browser (React SPA)
    │
    ▼ HTTPS/WSS
NGINX (reverse proxy + TLS + static files)
    │
    ├─▶ /api/*     → NestJS API (:3000)
    └─▶ /socket.io → EventsGateway (Socket.IO)
                          │
                          ▼
                    PostgreSQL 16 (managed)
```

→ [Full architecture diagram with Mermaid](docs/architecture.md)  
→ [Database ER diagram](docs/er-diagram.md)

---

## Quick Start (Local Development)

**Prerequisites:** Node.js 20+, Docker

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/sentinelflow.git
cd sentinelflow

# Install
npm install

# Start PostgreSQL
docker compose up -d

# Run migrations + seed demo data
cd apps/api
npx prisma migrate dev --name init
npx prisma db seed
cd ../..

# Start API (Terminal 1)
npm run start:dev --workspace=apps/api

# Start Frontend (Terminal 2)
npm run dev --workspace=apps/web

# Open browser
open http://localhost:5173
```

**Demo login:** `admin@sentinelflow.local` / `Admin123!`

See the [Demo Guide](docs/demo-guide.md) for a full 15-minute walk-through.

---

## Running Tests

```bash
# All unit tests (119 passing)
npm test --workspace=apps/api

# With coverage report
npm run test:cov --workspace=apps/api

# Integration tests (requires running database)
npx jest tests/integration/ --testTimeout=30000
```

---

## Production Deployment

```bash
# Configure production environment
cp .env.production.example .env.production
# Fill in DATABASE_URL, JWT_SECRET, CORS_ORIGIN, N8N_* values

# Build and start
docker compose -f docker-compose.prod.yml --env-file .env.production up -d --build
```

→ [Full deployment guide](docs/deployment.md)  
→ [Backup & recovery runbook](docs/backup-and-recovery.md)

---

## API Documentation

Interactive Swagger UI available at `/api/docs` when the server is running:

```
http://localhost:3000/api/docs
```

→ [API reference](docs/api-reference.md)

---

## Security Design

→ [Security architecture document](docs/security-architecture.md)

Key controls:
- Zero-trust tenant isolation (org membership verified server-side on every request)
- Refresh token stored as SHA-256 hash only; rotated on every exchange
- WebSocket CORS enforces exact same origin whitelist as HTTP
- Detection engine REGEX patterns are guarded against ReDoS

---

## Project Structure

```
sentinelflow/
├── apps/
│   ├── api/                    # NestJS backend
│   │   ├── src/
│   │   │   ├── auth/           # JWT + Argon2id + refresh sessions
│   │   │   ├── incidents/      # Incident CRUD + timeline + n8n dispatch
│   │   │   ├── alerts/         # Alert ingestion + detection eval
│   │   │   ├── detection/      # Rule engine + MITRE + risk scoring
│   │   │   ├── threat-intel/   # Feed sync + IOC normalization
│   │   │   ├── ioc/            # IOC validation + org-scoped CRUD
│   │   │   ├── analytics/      # MTTA/MTTR metrics
│   │   │   ├── audit/          # Structured audit log
│   │   │   ├── events/         # WebSocket gateway (Socket.IO)
│   │   │   ├── health/         # DB + n8n connectivity health
│   │   │   ├── n8n/            # Webhook dispatch + callback handler
│   │   │   └── common/         # Middleware (correlation IDs)
│   │   └── prisma/             # Schema + migrations + seed
│   └── web/                    # React 18 + Vite frontend
│       └── src/
│           ├── components/     # Dashboard, auth, detection, intel views
│           ├── context/        # AuthContext, SocketContext
│           └── services/       # secureFetch API client
├── packages/
│   └── shared/                 # Shared TypeScript types (monorepo)
├── tests/
│   └── integration/            # Tenant isolation + auth + feed tests
├── docs/                       # Architecture, ER, deployment, security
├── nginx/                      # NGINX reverse proxy config
├── docker-compose.yml          # Local development stack
└── docker-compose.prod.yml     # Production deployment
```

---

## License

MIT — See [LICENSE](LICENSE) for details.

---

*Built as a full-stack portfolio project demonstrating production-grade security engineering, real-time systems design, and AI automation integration.*
