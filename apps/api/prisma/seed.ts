import { PrismaClient, Severity, IncidentStatus, IOCType, UserRole } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Starting SentinelFlow database seed...');

  // 1. Create / Upsert Default SOC Analyst User
  const analyst = await prisma.user.upsert({
    where: { email: 'sarah.chen@sentinelflow.local' },
    update: {},
    create: {
      id: 'USR-SOC-001',
      email: 'sarah.chen@sentinelflow.local',
      name: 'Sarah Chen',
      role: UserRole.SOC_LEAD,
      tenantId: 'default-tenant',
    },
  });

  const cloudAnalyst = await prisma.user.upsert({
    where: { email: 'alex.rivera@sentinelflow.local' },
    update: {},
    create: {
      id: 'USR-SOC-002',
      email: 'alex.rivera@sentinelflow.local',
      name: 'Alex Rivera',
      role: UserRole.ANALYST,
      tenantId: 'default-tenant',
    },
  });

  // 2. Upsert Sample Incidents
  const inc1 = await prisma.incident.upsert({
    where: { id: 'INC-2026-001' },
    update: {},
    create: {
      id: 'INC-2026-001',
      title: 'Suspicious PowerShell Execution & EDR Evasion',
      description:
        'Endpoint telemetry flagged obfuscated PowerShell command executing base64 payload matching Mimikatz signatures on workstation WS-FIN-04.',
      severity: Severity.CRITICAL,
      status: IncidentStatus.INVESTIGATING,
      tenantId: 'default-tenant',
      assignedToId: analyst.id,
      aiSummary:
        'High-confidence credential dumping attempt following initial access via spear-phishing attachment.',
      aiRiskScore: 0.94,
      mitigationSteps: [
        'Isolate host WS-FIN-04 via EDR agent',
        'Revoke active Kerberos ticket-granting tickets for user j.doe',
        'Block egress communication to 198.51.100.42 at perimeter firewall',
      ],
      aiAnalysis: {
        summary:
          'High-confidence credential dumping attempt following initial access via spear-phishing attachment.',
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
      createdAt: new Date(Date.now() - 7200000),
      updatedAt: new Date(Date.now() - 1800000),
      iocs: {
        create: [
          {
            id: 'IOC-001',
            type: IOCType.IP,
            value: '198.51.100.42',
            threatScore: 89,
            enrichedData: { abuseScore: 89, country: 'NL', asn: 'AS49981' },
            createdAt: new Date(Date.now() - 3600000),
          },
          {
            id: 'IOC-002',
            type: IOCType.HASH_SHA256,
            value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            threatScore: 95,
            enrichedData: { detectionRate: '58/72', signature: 'HackTool:Win32/Mimikatz.A' },
            createdAt: new Date(Date.now() - 3500000),
          },
        ],
      },
    },
  });

  const inc2 = await prisma.incident.upsert({
    where: { id: 'INC-2026-002' },
    update: {},
    create: {
      id: 'INC-2026-002',
      title: 'Anomalous Cloud API Invocations from Foreign ASN',
      description:
        'IAM user prod-deployer invoked DescribeInstances and GetSecretValue from unrecognized IP range in AS13335 outside normal deployment window.',
      severity: Severity.HIGH,
      status: IncidentStatus.TRIAGED,
      tenantId: 'default-tenant',
      assignedToId: cloudAnalyst.id,
      aiSummary: 'Potential long-lived AWS IAM access key compromise. Secret exfiltration attempt detected.',
      aiRiskScore: 0.88,
      mitigationSteps: [
        'Deactivate compromised IAM access key prod-deployer-ak-02',
        'Audit AWS CloudTrail events for preceding 24 hours',
        'Rotate all production secrets accessed during the anomalous session',
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
      createdAt: new Date(Date.now() - 5400000),
      updatedAt: new Date(Date.now() - 3600000),
      iocs: {
        create: [
          {
            id: 'IOC-003',
            type: IOCType.IP,
            value: '203.0.113.88',
            threatScore: 78,
            enrichedData: { asn: 'AS13335', isp: 'CloudFlare proxy' },
            createdAt: new Date(Date.now() - 5400000),
          },
        ],
      },
    },
  });

  const inc3 = await prisma.incident.upsert({
    where: { id: 'INC-2026-003' },
    update: {},
    create: {
      id: 'INC-2026-003',
      title: 'Repeated Password Spraying on SSO Gateway',
      description:
        'Over 4,500 authentication failures recorded against Okta SSO endpoint across 120 unique user accounts over 10 minutes.',
      severity: Severity.MEDIUM,
      status: IncidentStatus.CONTAINED,
      tenantId: 'default-tenant',
      aiSummary:
        'Automated distributed password spraying attempt. Rate-limiting and geo-blocking successfully activated.',
      aiRiskScore: 0.35,
      mitigationSteps: [
        'Maintain perimeter IP blocklist for 48 hours',
        'Enforce FIDO2 WebAuthn prompts on targeted accounts',
      ],
      aiAnalysis: {
        summary:
          'Automated distributed password spraying attempt. Rate-limiting and geo-blocking successfully activated.',
        riskAssessment: 'Low residual risk. No successful authentications identified.',
        recommendedMitigations: [
          'Maintain perimeter IP blocklist for 48 hours',
          'Enforce FIDO2 WebAuthn prompts on targeted accounts',
        ],
        confidenceScore: 0.96,
        analyzedAt: new Date(Date.now() - 14000000).toISOString(),
        modelUsed: 'SentinelFlow-SecurityLLM-v2',
      },
      createdAt: new Date(Date.now() - 14400000),
      updatedAt: new Date(Date.now() - 12000000),
      iocs: {
        create: [
          {
            id: 'IOC-004',
            type: IOCType.IP,
            value: '192.0.2.14',
            threatScore: 65,
            enrichedData: { abuseReports: 24 },
            createdAt: new Date(Date.now() - 14400000),
          },
        ],
      },
    },
  });

  // 3. Upsert Sample Alerts
  await prisma.securityAlert.upsert({
    where: { id: 'ALT-9821' },
    update: {},
    create: {
      id: 'ALT-9821',
      title: 'PowerShell EncodedCommand Execution',
      description: 'Host WS-FIN-04 executed powershell.exe -enc with elevated permissions.',
      severity: Severity.CRITICAL,
      source: 'CrowdStrike Falcon EDR',
      incidentId: inc1.id,
      tenantId: 'default-tenant',
      detectedAt: new Date(Date.now() - 3600000),
      createdAt: new Date(Date.now() - 3600000),
    },
  });

  await prisma.securityAlert.upsert({
    where: { id: 'ALT-9823' },
    update: {},
    create: {
      id: 'ALT-9823',
      title: 'LSASS Memory Read Access',
      description: 'Unsigned binary attempted OpenProcess on lsass.exe process ID 684.',
      severity: Severity.CRITICAL,
      source: 'Microsoft Defender for Endpoint',
      incidentId: inc1.id,
      tenantId: 'default-tenant',
      detectedAt: new Date(Date.now() - 3550000),
      createdAt: new Date(Date.now() - 3550000),
    },
  });

  await prisma.securityAlert.upsert({
    where: { id: 'ALT-9844' },
    update: {},
    create: {
      id: 'ALT-9844',
      title: 'AWS CloudTrail Root / Admin Console Access',
      description: 'ConsoleLogin event without MFA verification detected from unrecognized ASN.',
      severity: Severity.HIGH,
      source: 'AWS GuardDuty',
      incidentId: inc2.id,
      tenantId: 'default-tenant',
      detectedAt: new Date(Date.now() - 5400000),
      createdAt: new Date(Date.now() - 5400000),
    },
  });

  await prisma.securityAlert.upsert({
    where: { id: 'ALT-9810' },
    update: {},
    create: {
      id: 'ALT-9810',
      title: 'Brute Force / Password Spray Attack',
      description: 'High volume of 401 Unauthorized responses from Okta identity provider.',
      severity: Severity.MEDIUM,
      source: 'Okta System Log',
      incidentId: inc3.id,
      tenantId: 'default-tenant',
      detectedAt: new Date(Date.now() - 14400000),
      createdAt: new Date(Date.now() - 14400000),
    },
  });

  console.log('✅ SentinelFlow seed completed successfully.');
}

main()
  .catch((e) => {
    console.error('❌ Error during seed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
