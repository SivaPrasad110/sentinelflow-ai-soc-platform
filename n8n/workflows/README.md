# SentinelFlow Automation Workflows (n8n Cloud)

This directory contains production automation workflows, playbooks, and integration documentation for SentinelFlow's integration with **n8n Cloud** (or self-hosted n8n).

## Architecture Overview

```
 [Security Telemetry / EDR / SIEM]
              │
              ▼
   [SentinelFlow NestJS API]
              │
              ├─► Persists to PostgreSQL via Prisma
              │
              └─► HTTP POST Webhook Trigger
                        │
                        ▼
            [n8n Automation Engine]
                        │
       ┌────────────────┼────────────────┐
       ▼                ▼                ▼
 [IOC Threat       [AI Incident     [SOC Notification
  Enrichment]       Analysis]        (Slack/Email)]
       │                │                │
       └────────────────┴────────────────┘
                        │
                        ▼
       [Update Incident Status in SentinelFlow]
```

## Available Workflows

### 1. Incident Automated Triage Playbook (`incident-triage-workflow.json`)
- **Trigger**: Webhook `POST /webhook/sentinelflow-triage`
- **Authentication**: Header verification via `X-SentinelFlow-Secret` (configured in `.env` as `N8N_WEBHOOK_SECRET`)
- **Workflow Steps**:
  1. **Webhook Receiver**: Receives incoming incident JSON from SentinelFlow API.
  2. **IOC Extractor**: Iterates through detected IPs, domains, and file hashes.
  3. **Threat Intelligence Enrichment**: Queries threat feeds (e.g. VirusTotal, AbuseIPDB).
  4. **AI Summary Generation**: Sends aggregated context to the AI model for risk scoring and mitigation recommendations.
  5. **Notification**: Posts high/critical alerts to SOC team communication channels.
  6. **Callback / Response**: Returns enriched incident analysis to SentinelFlow.

## How to Import Workflows into n8n Cloud

1. Log into your **n8n Cloud** instance (`https://<your-workspace>.app.n8n.cloud`).
2. Go to **Workflows** > **Add Workflow**.
3. Click the three dots `...` in the top-right corner and select **Import from File...**.
4. Select `n8n/workflows/incident-triage-workflow.json`.
5. Update your webhook path and activate the workflow.
6. Copy the generated Webhook URL and paste it into `.env`:
   ```bash
   N8N_WEBHOOK_URL="https://your-n8n-cloud-instance.app.n8n.cloud/webhook/sentinelflow-triage"
   ```
