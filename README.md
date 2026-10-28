# SentinelFlow — AI Security Operations Platform

SentinelFlow is a production-oriented AI Security Operations Center (SOC) platform designed to streamline incident ingestion, automated threat intelligence enrichment, and AI-assisted triage workflows.

---

## Architecture Overview

- **Monorepo Structure**:
  - `apps/web`: React 18, TypeScript, Vite, Tailwind CSS (SOC Analyst Dashboard)
  - `apps/api`: NestJS 10, TypeScript, REST APIs, Swagger OpenAPI documentation
  - `packages/shared`: Shared TypeScript domain models (Incidents, IOCs, Alerts, Health status)
  - `n8n/workflows`: n8n Cloud / self-hosted webhook automation workflows and playbooks
  - `tests`: Integration and end-to-end test suites
- **Database**: PostgreSQL with Prisma ORM
- **Automation Engine**: n8n Cloud webhook integration

---

## Prerequisites

Before starting, ensure you have the following installed:
1. **Node.js**: v20+ or v24+ (Verified installed on system)
2. **npm**: v10+ or v11+ (Verified installed on system)
3. **Git**: Installed (Verified on system)
4. **PostgreSQL / Docker**: Required for persisting data in PostgreSQL via Prisma. (If Docker Desktop is not yet installed or running, the API runs with rich development seed data out-of-the-box).

---

## Quickstart & Installation

### 1. Configure Environment Variables
Copy the `.env.example` file to `.env`:
```bash
# In the project root (sentinelflow/)
cp .env.example .env
```

### 2. Install Dependencies
Run `npm install` from the project root to install workspace dependencies:
```bash
npm install
```

### 3. Build Shared Packages
Compile the shared TypeScript definitions first:
```bash
npm run build:shared
```

---

## Running Applications Locally

### Option A: Run Both Applications Simultaneously
You can run each application in a separate terminal:

**Terminal 1 — Backend REST API (NestJS):**
```bash
npm run dev:api
```
- API Base URL: `http://localhost:3000/api/v1`
- Interactive Swagger API Docs: `http://localhost:3000/api/docs`
- Health Endpoint: `http://localhost:3000/api/v1/health`

**Terminal 2 — Frontend Dashboard (React + Vite):**
```bash
npm run dev:web
```
- Web Application: `http://localhost:5173`
- The Vite development server automatically proxies `/api` calls to the backend on port 3000.

---

## Database Setup (PostgreSQL + Prisma)

When your PostgreSQL instance or Docker Desktop is ready:

1. **Start PostgreSQL via Docker Compose**:
   ```bash
   docker compose up -d
   ```
2. **Generate Prisma Client**:
   ```bash
   npm --workspace=@sentinelflow/api run prisma:generate
   ```
3. **Run Database Migrations**:
   ```bash
   npm --workspace=@sentinelflow/api run prisma:migrate
   ```

---

## Testing

Run tests across all workspaces:
```bash
npm run test
```
Or run API unit and integration tests specifically:
```bash
npm --workspace=@sentinelflow/api run test
```

---

## n8n Cloud Playbook Automation

SentinelFlow connects to n8n Cloud via secure webhooks:
1. Import `n8n/workflows/incident-triage-workflow.json` into your n8n workspace.
2. Set the `N8N_WEBHOOK_URL` and `N8N_WEBHOOK_SECRET` in `.env`.
3. High and Critical incidents can trigger the automated containment and enrichment playbook.
