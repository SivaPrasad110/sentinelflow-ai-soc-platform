import { Injectable, NotFoundException } from '@nestjs/common';
import { Incident, IncidentStatus, AlertSeverity } from '@sentinelflow/shared';

@Injectable()
export class IncidentsService {
  // Seeded mock incidents for development initialization
  private incidents: Incident[] = [
    {
      id: 'INC-2026-001',
      title: 'Suspicious PowerShell Execution & EDR Evasion',
      description: 'Endpoint telemetry flagged obfuscated PowerShell command executing base64 payload matching Mimikatz signatures on workstation WS-FIN-04.',
      severity: 'CRITICAL',
      status: 'INVESTIGATING',
      sourceAlertIds: ['ALT-9821', 'ALT-9823'],
      iocs: [
        {
          id: 'IOC-001',
          type: 'IP',
          value: '198.51.100.42',
          threatScore: 89,
          createdAt: new Date(Date.now() - 3600000).toISOString(),
        },
        {
          id: 'IOC-002',
          type: 'HASH_SHA256',
          value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          threatScore: 95,
          createdAt: new Date(Date.now() - 3500000).toISOString(),
        },
      ],
      aiAnalysis: {
        summary: 'High-confidence credential dumping attempt following initial access via spear-phishing attachment.',
        riskAssessment: 'Critical risk of lateral movement across internal corporate subnet within next 30 minutes.',
        recommendedMitigations: [
          'Isolate host WS-FIN-04 via EDR agent',
          'Revoke active Kerberos ticket-granting tickets for user j.doe',
          'Block egress communication to 198.51.100.42 at perimeter firewall',
        ],
        confidenceScore: 0.94,
        analyzedAt: new Date(Date.now() - 1800000).toISOString(),
        modelUsed: 'SentinelFlow-SecurityLLM-v2',
      },
      assignedTo: 'Lead SOC Analyst Sarah Chen',
      createdAt: new Date(Date.now() - 7200000).toISOString(),
      updatedAt: new Date(Date.now() - 1800000).toISOString(),
    },
    {
      id: 'INC-2026-002',
      title: 'Anomalous Cloud API Invocations from Foreign ASN',
      description: 'IAM user prod-deployer invoked DescribeInstances and GetSecretValue from unrecognized IP range in AS13335 outside normal deployment window.',
      severity: 'HIGH',
      status: 'TRIAGED',
      sourceAlertIds: ['ALT-9844'],
      iocs: [
        {
          id: 'IOC-003',
          type: 'IP',
          value: '203.0.113.88',
          threatScore: 78,
          createdAt: new Date(Date.now() - 5400000).toISOString(),
        },
      ],
      aiAnalysis: {
        summary: 'Potential long-lived AWS IAM access key compromise. Secret exfiltration attempt detected.',
        riskAssessment: 'High risk of unauthorized production infrastructure access.',
        recommendedMitigations: [
          'Deactivate compromised IAM access key prod-deployer-ak-02',
          'Audit AWS CloudTrail events for preceding 24 hours',
          'Rotate all production secrets accessed during the anomalous session',
        ],
        confidenceScore: 0.88,
        analyzedAt: new Date(Date.now() - 3600000).toISOString(),
        modelUsed: 'SentinelFlow-SecurityLLM-v2',
      },
      assignedTo: 'Cloud Security Analyst Alex Rivera',
      createdAt: new Date(Date.now() - 5400000).toISOString(),
      updatedAt: new Date(Date.now() - 3600000).toISOString(),
    },
    {
      id: 'INC-2026-003',
      title: 'Repeated Password Spraying on SSO Gateway',
      description: 'Over 4,500 authentication failures recorded against Okta SSO endpoint across 120 unique user accounts over 10 minutes.',
      severity: 'MEDIUM',
      status: 'CONTAINED',
      sourceAlertIds: ['ALT-9810'],
      iocs: [
        {
          id: 'IOC-004',
          type: 'IP',
          value: '192.0.2.14',
          threatScore: 65,
          createdAt: new Date(Date.now() - 14400000).toISOString(),
        },
      ],
      aiAnalysis: {
        summary: 'Automated distributed password spraying attempt. Rate-limiting and geo-blocking successfully activated.',
        riskAssessment: 'Low residual risk. No successful authentications identified.',
        recommendedMitigations: [
          'Maintain perimeter IP blocklist for 48 hours',
          'Enforce FIDO2 WebAuthn prompts on targeted accounts',
        ],
        confidenceScore: 0.96,
        analyzedAt: new Date(Date.now() - 14000000).toISOString(),
        modelUsed: 'SentinelFlow-SecurityLLM-v2',
      },
      assignedTo: 'Automated SOC Playbook (n8n)',
      createdAt: new Date(Date.now() - 14400000).toISOString(),
      updatedAt: new Date(Date.now() - 12000000).toISOString(),
    },
  ];

  findAll(): Incident[] {
    return this.incidents;
  }

  findById(id: string): Incident {
    const incident = this.incidents.find((inc) => inc.id === id);
    if (!incident) {
      throw new NotFoundException(`Incident with ID "${id}" was not found.`);
    }
    return incident;
  }

  create(data: Partial<Incident>): Incident {
    const newIncident: Incident = {
      id: `INC-2026-${String(this.incidents.length + 1).padStart(3, '0')}`,
      title: data.title || 'Untitled Security Incident',
      description: data.description || 'No description provided',
      severity: data.severity || 'MEDIUM',
      status: data.status || 'NEW',
      sourceAlertIds: data.sourceAlertIds || [],
      iocs: data.iocs || [],
      aiAnalysis: data.aiAnalysis,
      assignedTo: data.assignedTo,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    this.incidents.unshift(newIncident);
    return newIncident;
  }
}
