# SentinelFlow — Deployment Guide

> **Target audience:** Self-hosting operators and portfolio reviewers  
> **Stack:** NestJS 10 · React 18/Vite · PostgreSQL 16 · Socket.IO · n8n Cloud · Docker

---

## Prerequisites

| Tool | Version | Install |
|---|---|---|
| Docker Engine | ≥ 24 | https://docs.docker.com/engine/install/ |
| Docker Compose | ≥ 2.24 | Included with Docker Desktop |
| Node.js (local dev only) | 20 LTS | https://nodejs.org |
| Git | Any | https://git-scm.com |

---

## Option A — Local Development

### 1. Clone and Install

```bash
git clone https://github.com/YOUR_USERNAME/sentinelflow.git
cd sentinelflow
npm install
```

### 2. Start PostgreSQL

```bash
docker compose up -d   # Starts postgres on 127.0.0.1:5433
```

### 3. Configure Environment

```bash
# The root .env is pre-configured for local development.
# Review apps/api/.env — it inherits from the root.
# Never commit .env files with real secrets.
cat .env
```

### 4. Run Database Migrations

```bash
cd apps/api
npx prisma migrate dev --name init   # Creates tables + seed data
npx prisma db seed                   # Seeds demo organizations and users
cd ../..
```

### 5. Start Development Servers

```bash
# Terminal 1: API (http://localhost:3000)
npm run start:dev --workspace=apps/api

# Terminal 2: Web (http://localhost:5173)
npm run dev --workspace=apps/web
```

### 6. Demo Accounts (Local Only)

After seeding, the following accounts are available:

| Email | Password | Role |
|---|---|---|
| `admin@sentinelflow.local` | `Admin123!` | ADMIN |
| `analyst@sentinelflow.local` | `Analyst123!` | ANALYST |
| `viewer@sentinelflow.local` | `Viewer123!` | VIEWER |

> ⚠️ **These accounts are for local demo ONLY. Change or delete them before any public deployment.**

---

## Option B — Production Docker Compose

### 1. Provision a Managed PostgreSQL Database

Choose one:
- **Supabase** (recommended free tier): https://supabase.com → New Project → Connection String
- **Neon** (serverless, branch-based): https://neon.tech
- **Railway**: https://railway.app/new → Add PostgreSQL
- **Render**: https://render.com → New → PostgreSQL

Copy the connection string — it will look like:  
`postgresql://user:password@host:5432/dbname?sslmode=require`

### 2. Configure Production Environment

```bash
cp .env.production.example .env.production
# Edit .env.production — fill in ALL [REQUIRED] values:
#   DATABASE_URL    ← your managed PostgreSQL connection string
#   JWT_SECRET      ← generate: node -e "require('crypto').randomBytes(64).toString('base64url')" | pbcopy
#   CORS_ORIGIN     ← https://app.yourdomain.com
#   N8N_WEBHOOK_URL ← your n8n Cloud webhook URL
#   N8N_WEBHOOK_SECRET ← your n8n shared secret
#   VITE_API_BASE_URL  ← https://api.yourdomain.com/api/v1
nano .env.production
```

### 3. Build and Start

```bash
# Build and start in detached mode
docker compose -f docker-compose.prod.yml --env-file .env.production up -d --build

# Watch startup logs
docker compose -f docker-compose.prod.yml logs -f api
```

The API runs migrations automatically on startup (`prisma migrate deploy`).

### 4. Verify Health

```bash
# Should return: {"status":"ok","services":{"api":"healthy","database":"connected",...}}
curl http://localhost:3000/api/v1/health
```

### 5. Seed Initial Data (First Deployment Only)

```bash
docker exec sentinelflow-api sh -c "cd apps/api && npx prisma db seed"
```

---

## Option C — Platform-as-a-Service

### Railway (API + Database)

1. Connect your GitHub repository to Railway
2. Add a PostgreSQL service — Railway auto-populates `DATABASE_URL`
3. Set environment variables in the Railway dashboard (from `.env.production.example`)
4. Set `RAILWAY_DOCKERFILE_PATH=apps/api/Dockerfile`
5. Deploy

### Render (API + Static Web)

1. New Web Service → Connect GitHub → set `Root Directory: apps/api`
2. Set `Dockerfile Path: apps/api/Dockerfile`
3. Add environment variables from `.env.production.example`
4. New Static Site → Connect GitHub → set `Root Directory: apps/web`
5. Set Build Command: `npm run build --workspace=apps/web`
6. Set Publish Directory: `apps/web/dist`

---

## n8n Cloud Integration

SentinelFlow dispatches incident triage to n8n Cloud webhooks. To configure:

1. Log in to [n8n Cloud](https://app.n8n.cloud)
2. Create a new workflow with a **Webhook** trigger node
3. Set the webhook path to: `/sentinelflow/incident-triage`
4. Enable **Header Auth** and set the header name to `x-n8n-secret`
5. Copy the webhook URL and shared secret to your production environment:
   ```
   N8N_WEBHOOK_URL=https://YOUR-INSTANCE.app.n8n.cloud/webhook/sentinelflow/incident-triage
   N8N_WEBHOOK_SECRET=your-shared-secret
   ```
6. Add response nodes in n8n to POST results back to:  
   `POST /api/v1/n8n/callback/:executionId`

---

## HTTPS with Let's Encrypt (Self-Hosted)

If you are running your own server (not using a managed platform):

```bash
# Install Certbot
apt install certbot python3-certbot-nginx

# Obtain certificate
certbot --nginx -d yourdomain.com -d api.yourdomain.com

# Auto-renewal (runs twice daily)
systemctl enable certbot.timer
```

Then update `nginx/app.conf` to use the obtained certificate paths and redirect HTTP → HTTPS.

---

## Health Verification Checklist

After deployment, verify:

```bash
# ✅ API health
curl https://api.yourdomain.com/api/v1/health

# ✅ Swagger docs accessible
curl -I https://api.yourdomain.com/api/docs

# ✅ Frontend loads
curl -I https://app.yourdomain.com

# ✅ WebSocket connectivity (browser console)
# const socket = io('https://api.yourdomain.com/events', { auth: { token: 'ACCESS_TOKEN' } });
# socket.on('connect', () => console.log('WS connected'));

# ✅ Login works
curl -X POST https://api.yourdomain.com/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@yourdomain.com","password":"YOUR_PASSWORD"}'
```

---

## Updating Production

```bash
# Pull latest changes
git pull origin main

# Rebuild and restart (zero-downtime strategy: rolling restart)
docker compose -f docker-compose.prod.yml --env-file .env.production up -d --build --no-deps api
docker compose -f docker-compose.prod.yml --env-file .env.production up -d --build --no-deps web
```

Migrations run automatically on API startup.
