/**
 * SentinelFlow Shared Domain Types
 * Production-oriented AI Security Operations Platform
 */

export type AlertSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type IncidentStatus =
  | 'NEW'
  | 'TRIAGED'
  | 'INVESTIGATING'
  | 'CONTAINED'
  | 'RESOLVED'
  | 'CLOSED';

export type IOCType = 'IP' | 'DOMAIN' | 'HASH_SHA256' | 'HASH_MD5' | 'URL' | 'EMAIL';

export type OrgRole = 'ADMIN' | 'ANALYST' | 'VIEWER';

export interface Organization {
  id: string;
  name: string;
  slug: string;
  createdAt: string;
}

export interface OrganizationMembership {
  id: string;
  organizationId: string;
  organizationName: string;
  organizationSlug: string;
  role: OrgRole;
}

export interface UserProfile {
  id: string;
  email: string;
  name: string;
  activeOrganizationId: string;
  activeRole: OrgRole;
  memberships: OrganizationMembership[];
  createdAt: string;
}

export interface AuthResponse {
  accessToken: string;
  user: UserProfile;
}

export interface IndicatorOfCompromise {
  id: string;
  type: IOCType;
  value: string;
  threatScore?: number;
  enrichedData?: Record<string, unknown>;
  createdAt: string;
}

export interface SecurityAlert {
  id: string;
  title: string;
  description: string;
  severity: AlertSeverity;
  source: string; // e.g. 'SIEM', 'EDR', 'CloudTrail', 'WAF'
  rawEvent?: Record<string, unknown>;
  organizationId?: string;
  detectedAt: string;
  createdAt: string;
}

export interface AIAnalysisResult {
  summary: string;
  riskAssessment: string;
  recommendedMitigations: string[];
  confidenceScore: number; // 0.0 - 1.0
  analyzedAt: string;
  modelUsed: string;
}

export interface Incident {
  id: string;
  title: string;
  description: string;
  severity: AlertSeverity;
  status: IncidentStatus;
  organizationId?: string;
  sourceAlertIds: string[];
  iocs: IndicatorOfCompromise[];
  aiAnalysis?: AIAnalysisResult;
  analyses?: IncidentAnalysisRecord[];
  assignedTo?: string;
  createdAt: string;
  updatedAt: string;
}

export type AnalysisStatus = 'PENDING' | 'COMPLETED' | 'FAILED';

export type TriageSeverityAssessment =
  | 'informational'
  | 'low'
  | 'medium'
  | 'high'
  | 'critical'
  | AlertSeverity;

export interface N8nTriageResponseData {
  summary: string;
  severity_assessment: TriageSeverityAssessment;
  confidence: number;
  evidence: string[];
  potential_impact: string;
  recommended_actions: string[];
  missing_information: string[];
  requires_human_review: boolean;
}

export interface IncidentAnalysisRecord {
  id: string;
  incidentId: string;
  organizationId: string;
  status: AnalysisStatus;
  eventId: string;
  workflowId?: string;
  executionId?: string;
  model?: string;
  summary?: string;
  severityAssessment?: string;
  confidence?: number;
  evidence: string[];
  potentialImpact?: string;
  recommendedActions: string[];
  missingInformation: string[];
  requiresHumanReview: boolean;
  errorMessage?: string;
  durationMs?: number;
  triggeredById?: string;
  createdAt: string;
  completedAt?: string;
}

export interface N8nTriageRequestPayload {
  eventId: string;
  incidentId: string;
  title: string;
  description: string;
  severity: AlertSeverity;
  status: IncidentStatus;
  organizationId: string;
  iocs: Array<{ type: IOCType; value: string; threatScore?: number }>;
  detectedAlertsCount: number;
  detectedAlertsSummary?: Array<{ title: string; source: string; severity: AlertSeverity }>;
  timestamp: string;
}

export interface WorkflowAutomationTrigger {
  workflowId: string;
  triggerEvent: 'INCIDENT_CREATED' | 'IOC_DETECTED' | 'MANUAL_DISPATCH';
  incidentId: string;
  payload: Record<string, unknown>;
  timestamp: string;
}

export interface WorkflowExecutionResult {
  executionId: string;
  workflowId: string;
  status: 'PENDING' | 'RUNNING' | 'SUCCESS' | 'FAILED';
  outputSummary?: string;
  triggeredAt: string;
  completedAt?: string;
}

export interface SystemHealthResponse {
  status: 'ok' | 'degraded' | 'error';
  timestamp: string;
  uptimeSeconds: number;
  environment: string;
  version: string;
  services: {
    api: 'healthy' | 'unhealthy';
    database: 'connected' | 'disconnected' | 'unconfigured';
    n8n: 'connected' | 'reachable' | 'unreachable' | 'configured' | 'unconfigured';
  };
}
