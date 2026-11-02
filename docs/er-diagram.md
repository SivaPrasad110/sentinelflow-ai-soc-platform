# SentinelFlow — Database ER Diagram

> Generated from `apps/api/prisma/schema.prisma`  
> PostgreSQL 16 with Prisma ORM  
> All tables enforce tenant isolation via `organizationId`

---

```mermaid
erDiagram
    Organization {
        uuid id PK
        string name
        string slug UK
        datetime createdAt
        datetime updatedAt
    }

    User {
        uuid id PK
        string email UK
        string name
        string passwordHash
        UserRole role
        string tenantId
        datetime createdAt
        datetime updatedAt
    }

    OrganizationMembership {
        uuid id PK
        uuid userId FK
        uuid organizationId FK
        Role role
        datetime createdAt
        datetime updatedAt
    }

    RefreshSession {
        uuid id PK
        uuid userId FK
        string tokenHash UK
        string userAgent
        string ipAddress
        datetime expiresAt
        datetime revokedAt
        datetime createdAt
    }

    Incident {
        uuid id PK
        string title
        string description
        Severity severity
        IncidentStatus status
        string tenantId
        uuid organizationId FK
        uuid assignedToId FK
        string aiSummary
        float aiRiskScore
        string[] mitigationSteps
        json aiAnalysis
        datetime acknowledgedAt
        datetime resolvedAt
        datetime closedAt
        datetime createdAt
        datetime updatedAt
    }

    SecurityAlert {
        uuid id PK
        string title
        string description
        Severity severity
        string source
        json rawPayload
        string tenantId
        uuid organizationId FK
        uuid incidentId FK
        datetime detectedAt
        datetime createdAt
    }

    IndicatorOfCompromise {
        uuid id PK
        IOCType type
        string value
        float threatScore
        float confidence
        Severity severity
        string source
        string description
        uuid organizationId FK
        uuid incidentId FK
        datetime firstSeen
        datetime lastSeen
        string[] tags
        string[] mitreTactics
        string[] mitreTechniques
        boolean isActive
        json rawFeedData
        json enrichedData
        datetime createdAt
        datetime updatedAt
    }

    ThreatFeed {
        uuid id PK
        string name
        string feedUrl
        string feedType
        string format
        uuid organizationId FK
        boolean enabled
        datetime lastFetchedAt
        int itemCount
        string status
        string errorMessage
        string scheduleCron
        datetime createdAt
        datetime updatedAt
    }

    DetectionRule {
        uuid id PK
        string name
        string description
        uuid organizationId FK
        Severity severity
        string ruleType
        json criteria
        string mitreTactic
        string mitreTechnique
        string mitreTechniqueId
        boolean enabled
        datetime lastTriggeredAt
        int triggerCount
        datetime createdAt
        datetime updatedAt
    }

    SecurityFinding {
        uuid id PK
        uuid organizationId FK
        uuid ruleId FK
        string title
        string description
        Severity severity
        float riskScore
        json riskBreakdown
        json evidence
        string mitreTactic
        string mitreTechnique
        string mitreTechniqueId
        string alertId
        string incidentId
        string fingerprint
        string status
        datetime createdAt
        datetime updatedAt
    }

    IncidentAnalysis {
        uuid id PK
        uuid incidentId FK
        uuid organizationId FK
        AnalysisStatus status
        string eventId UK
        string workflowId
        string executionId
        string model
        string summary
        TriageSeverity severityAssessment
        float confidence
        string[] evidence
        string potentialImpact
        string[] recommendedActions
        string[] missingInformation
        boolean requiresHumanReview
        string errorMessage
        json rawResponse
        int durationMs
        uuid triggeredById FK
        datetime createdAt
        datetime completedAt
    }

    IncidentTimelineEvent {
        uuid id PK
        uuid incidentId FK
        uuid organizationId FK
        string type
        string message
        string userId
        string userName
        string userEmail
        json metadata
        datetime createdAt
    }

    WorkflowExecutionLog {
        uuid id PK
        string workflowId
        string executionId
        string status
        string outputSummary
        uuid incidentId FK
        datetime triggeredAt
        datetime completedAt
    }

    AuditLog {
        uuid id PK
        uuid organizationId FK
        string userId
        string userEmail
        string action
        string entityType
        string entityId
        json details
        string ipAddress
        string userAgent
        datetime createdAt
    }

    %% ─── Relationships ──────────────────────────────────────────────────────

    Organization ||--o{ OrganizationMembership : "has members"
    Organization ||--o{ Incident : "owns"
    Organization ||--o{ SecurityAlert : "owns"
    Organization ||--o{ IndicatorOfCompromise : "owns"
    Organization ||--o{ ThreatFeed : "manages"
    Organization ||--o{ DetectionRule : "defines"
    Organization ||--o{ SecurityFinding : "generates"
    Organization ||--o{ IncidentAnalysis : "analyzes"
    Organization ||--o{ IncidentTimelineEvent : "records"
    Organization ||--o{ AuditLog : "audits"

    User ||--o{ OrganizationMembership : "belongs to orgs"
    User ||--o{ RefreshSession : "has sessions"
    User ||--o{ Incident : "assigned to"
    User ||--o{ IncidentAnalysis : "triggers"

    Incident ||--o{ SecurityAlert : "linked alerts"
    Incident ||--o{ IndicatorOfCompromise : "linked iocs"
    Incident ||--o{ WorkflowExecutionLog : "workflow runs"
    Incident ||--o{ IncidentAnalysis : "ai analyses"
    Incident ||--o{ IncidentTimelineEvent : "timeline"

    DetectionRule ||--o{ SecurityFinding : "triggers"
```

---

## Tenant Isolation Key Indexes

| Table | Index | Purpose |
|---|---|---|
| `Incident` | `organizationId` | Filter incidents by tenant |
| `Incident` | `tenantId` | Legacy compatibility filter |
| `SecurityAlert` | `organizationId` | Filter alerts by tenant |
| `SecurityAlert` | `detectedAt` | Time-range queries |
| `IndicatorOfCompromise` | `organizationId` | Filter IOCs by tenant |
| `IndicatorOfCompromise` | `value` | IOC lookup during detection eval |
| `SecurityFinding` | `fingerprint` | Alert storm deduplication |
| `SecurityFinding` | `organizationId` | Filter findings by tenant |
| `DetectionRule` | `organizationId` | Load rules per tenant |
| `AuditLog` | `organizationId, createdAt` | Tenant audit pagination |
| `RefreshSession` | `tokenHash` | O(1) token lookup |
| `RefreshSession` | `userId` | Session revocation per user |

---

## Enumerations

| Enum | Values |
|---|---|
| `Severity` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `IncidentStatus` | `NEW`, `TRIAGED`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED` |
| `IOCType` | `IP`, `DOMAIN`, `HASH_SHA256`, `HASH_MD5`, `URL`, `EMAIL` |
| `Role` (org membership) | `VIEWER`, `ANALYST`, `ADMIN` |
| `UserRole` (global) | `ANALYST`, `SOC_LEAD`, `ADMIN` |
| `AnalysisStatus` | `PENDING`, `COMPLETED`, `FAILED` |
| `TriageSeverity` | `INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
