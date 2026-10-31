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
  confidence?: number;
  severity?: AlertSeverity;
  source?: string;
  description?: string;
  organizationId?: string;
  incidentId?: string;
  firstSeen?: string;
  lastSeen?: string;
  tags?: string[];
  mitreTactics?: string[];
  mitreTechniques?: string[];
  isActive?: boolean;
  rawFeedData?: Record<string, unknown>;
  enrichedData?: Record<string, unknown>;
  createdAt: string;
  updatedAt?: string;
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
  assignedToId?: string;
  assignedToName?: string;
  assignedToEmail?: string;
  acknowledgedAt?: string;
  resolvedAt?: string;
  closedAt?: string;
  timeline?: IncidentTimelineEventRecord[];
  createdAt: string;
  updatedAt: string;
}

export interface IncidentTimelineEventRecord {
  id: string;
  incidentId: string;
  organizationId: string;
  type: 'COMMENT' | 'STATUS_CHANGE' | 'ASSIGNMENT' | 'ALERT_LINKED' | 'AI_ANALYSIS_COMPLETED' | 'ACTION_TAKEN';
  message: string;
  userId?: string;
  userName?: string;
  userEmail?: string;
  metadata?: Record<string, unknown>;
  createdAt: string;
}

export interface AuditLogRecord {
  id: string;
  organizationId: string;
  userId?: string;
  userEmail?: string;
  action: string;
  entityType: string;
  entityId?: string;
  details?: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
  createdAt: string;
}

export interface OrgMember {
  id: string;
  userId: string;
  name: string;
  email: string;
  role: OrgRole;
}

export interface SOCMetricsResponse {
  overview: {
    totalIncidents: number;
    openIncidents: number;
    resolvedIncidents: number;
    activeAlertsCount: number;
    criticalIncidentsCount: number;
    meanTimeToAcknowledgeMinutes: number; // MTTA in minutes
    meanTimeToResolveMinutes: number; // MTTR in minutes
  };
  severityDistribution: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
  statusDistribution: Record<IncidentStatus, number>;
  alertTrends: Array<{
    date: string; // YYYY-MM-DD
    count: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  }>;
  analystWorkload: Array<{
    analystId: string;
    analystName: string;
    assignedCount: number;
  }>;
}

export interface AssignIncidentPayload {
  assignedToId: string | null;
}

export interface CreateCommentPayload {
  comment: string;
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

// ==========================================
// Phase 6: Threat Intelligence & Detection Engine
// ==========================================

export interface MitreTechnique {
  id: string; // e.g. 'T1059.001'
  name: string; // e.g. 'PowerShell'
  tactic: string; // e.g. 'Execution'
  tacticId: string; // e.g. 'TA0002'
  description: string;
  detectionGuidance?: string;
}

export const MITRE_ATTACK_TACTICS = [
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0002', name: 'Execution' },
  { id: 'TA0003', name: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation' },
  { id: 'TA0005', name: 'Defense Evasion' },
  { id: 'TA0006', name: 'Credential Access' },
  { id: 'TA0007', name: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement' },
  { id: 'TA0009', name: 'Collection' },
  { id: 'TA0011', name: 'Command and Control' },
  { id: 'TA0010', name: 'Exfiltration' },
  { id: 'TA0040', name: 'Impact' },
] as const;

export const MITRE_ATTACK_CATALOG: MitreTechnique[] = [
  {
    id: 'T1566',
    name: 'Phishing',
    tactic: 'Initial Access',
    tacticId: 'TA0001',
    description: 'Adversaries may send phishing messages with malicious attachments or links to gain initial access.',
  },
  {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    tactic: 'Initial Access',
    tacticId: 'TA0001',
    description: 'Adversaries may attempt to exploit vulnerabilities in Internet-facing software or web services.',
  },
  {
    id: 'T1059.001',
    name: 'Command and Scripting Interpreter: PowerShell',
    tactic: 'Execution',
    tacticId: 'TA0002',
    description: 'Adversaries may use PowerShell commands and scripts to execute code and automate actions on Windows endpoints.',
  },
  {
    id: 'T1059.003',
    name: 'Command and Scripting Interpreter: Windows Command Shell',
    tactic: 'Execution',
    tacticId: 'TA0002',
    description: 'Adversaries may abuse cmd.exe to execute commands or batch files.',
  },
  {
    id: 'T1053.005',
    name: 'Scheduled Task/Job: Scheduled Task',
    tactic: 'Persistence',
    tacticId: 'TA0003',
    description: 'Adversaries may abuse the Windows Task Scheduler to schedule execution of malware or persistent tasks.',
  },
  {
    id: 'T1547.001',
    name: 'Boot or Logon Autostart Execution: Registry Run Keys',
    tactic: 'Persistence',
    tacticId: 'TA0003',
    description: 'Adversaries may achieve persistence by adding program paths to Windows Registry Run keys.',
  },
  {
    id: 'T1078',
    name: 'Valid Accounts',
    tactic: 'Privilege Escalation',
    tacticId: 'TA0004',
    description: 'Adversaries may obtain and abuse credentials of existing legitimate accounts to maintain elevated access.',
  },
  {
    id: 'T1027',
    name: 'Obfuscated Files or Information',
    tactic: 'Defense Evasion',
    tacticId: 'TA0005',
    description: 'Adversaries may attempt to make an executable or script difficult to detect through base64 encoding or encryption.',
  },
  {
    id: 'T1562.001',
    name: 'Impair Defenses: Disable or Modify Tools',
    tactic: 'Defense Evasion',
    tacticId: 'TA0005',
    description: 'Adversaries may modify or disable security monitoring tools such as Microsoft Defender or EDR services.',
  },
  {
    id: 'T1003.001',
    name: 'OS Credential Dumping: LSASS Memory',
    tactic: 'Credential Access',
    tacticId: 'TA0006',
    description: 'Adversaries may attempt to dump credentials from the Local Security Authority Subsystem Service (LSASS) process memory.',
  },
  {
    id: 'T1110',
    name: 'Brute Force',
    tactic: 'Credential Access',
    tacticId: 'TA0006',
    description: 'Adversaries may use brute-force password guessing techniques to acquire access to accounts.',
  },
  {
    id: 'T1087',
    name: 'Account Discovery',
    tactic: 'Discovery',
    tacticId: 'TA0007',
    description: 'Adversaries may attempt to get a listing of valid local system or domain accounts.',
  },
  {
    id: 'T1046',
    name: 'Network Service Discovery',
    tactic: 'Discovery',
    tacticId: 'TA0007',
    description: 'Adversaries may attempt to get a listing of services running on remote hosts through port scanning.',
  },
  {
    id: 'T1021.001',
    name: 'Remote Services: Remote Desktop Protocol',
    tactic: 'Lateral Movement',
    tacticId: 'TA0008',
    description: 'Adversaries may log in to remote systems using RDP to expand their footprint across the network.',
  },
  {
    id: 'T1021.002',
    name: 'Remote Services: SMB/Windows Admin Shares',
    tactic: 'Lateral Movement',
    tacticId: 'TA0008',
    description: 'Adversaries may leverage SMB and Windows administrative shares (such as C$, ADMIN$) to move laterally.',
  },
  {
    id: 'T1071.001',
    name: 'Application Layer Protocol: Web Protocols',
    tactic: 'Command and Control',
    tacticId: 'TA0011',
    description: 'Adversaries may communicate using application layer protocols (HTTP, HTTPS) to blend in with normal network traffic.',
  },
  {
    id: 'T1486',
    name: 'Data Encrypted for Impact',
    tactic: 'Impact',
    tacticId: 'TA0040',
    description: 'Adversaries may encrypt data on target systems to interrupt availability of system and network resources (Ransomware).',
  },
];

export type ThreatFeedStatus = 'IDLE' | 'SYNCING' | 'ERROR' | 'COMPLETED';

export interface ThreatFeed {
  id: string;
  name: string;
  feedUrl: string;
  feedType: 'URLHAUS' | 'THREATFOX' | 'MALWARE_BAZAAR' | 'BLOCKLIST' | 'CUSTOM';
  format: 'JSON' | 'CSV' | 'TEXT';
  organizationId?: string;
  enabled: boolean;
  lastFetchedAt?: string;
  itemCount: number;
  status: ThreatFeedStatus;
  errorMessage?: string;
  createdAt: string;
  updatedAt: string;
}

export interface ThreatFeedSyncResult {
  feedId: string;
  feedName: string;
  status: 'SUCCESS' | 'FAILED';
  indicatorsImported: number;
  indicatorsUpdated: number;
  durationMs: number;
  errorMessage?: string;
}

export type DetectionRuleType = 'IOC_MATCH' | 'PATTERN' | 'THRESHOLD';

export interface DetectionRuleCriterion {
  field: string;
  operator: 'EQUALS' | 'CONTAINS' | 'STARTS_WITH' | 'REGEX' | 'IN' | 'GREATER_THAN';
  value: string | number | string[];
}

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  organizationId: string;
  severity: AlertSeverity;
  ruleType: DetectionRuleType;
  criteria: DetectionRuleCriterion[];
  mitreTactic?: string;
  mitreTechnique?: string;
  mitreTechniqueId?: string;
  enabled: boolean;
  lastTriggeredAt?: string;
  triggerCount: number;
  createdAt: string;
  updatedAt: string;
}

export type FindingStatus = 'NEW' | 'ANALYZED' | 'PROMOTED' | 'DISMISSED';

export interface RiskScoreBreakdown {
  baseSeverityScore: number;
  iocConfidenceScore: number;
  mitreImpactScore: number;
  evidenceBonus: number;
  totalScore: number; // 0 - 100
  riskLevel: AlertSeverity;
  rationale: string[];
}

export interface SecurityFinding {
  id: string;
  organizationId: string;
  ruleId?: string;
  ruleName?: string;
  title: string;
  description: string;
  severity: AlertSeverity;
  riskScore: number;
  riskBreakdown?: RiskScoreBreakdown;
  evidence: Record<string, unknown>;
  mitreTactic?: string;
  mitreTechnique?: string;
  mitreTechniqueId?: string;
  alertId?: string;
  incidentId?: string;
  fingerprint: string;
  status: FindingStatus;
  createdAt: string;
  updatedAt: string;
}

export interface CreateIocPayload {
  type: IOCType;
  value: string;
  severity?: AlertSeverity;
  confidence?: number;
  threatScore?: number;
  source?: string;
  description?: string;
  tags?: string[];
  mitreTactics?: string[];
  mitreTechniques?: string[];
  incidentId?: string;
}

export interface CreateDetectionRulePayload {
  name: string;
  description: string;
  severity: AlertSeverity;
  ruleType: DetectionRuleType;
  criteria: DetectionRuleCriterion[];
  mitreTactic?: string;
  mitreTechnique?: string;
  mitreTechniqueId?: string;
  enabled?: boolean;
}

export interface ThreatIntelStatsResponse {
  totalIocs: number;
  activeIocs: number;
  feedCount: number;
  iocsByType: Record<IOCType, number>;
  iocsBySeverity: Record<AlertSeverity, number>;
  totalFindings: number;
  unresolvedFindings: number;
  mitreCoverageCount: number;
}
