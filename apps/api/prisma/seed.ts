import { PrismaClient, Severity, IncidentStatus, IOCType, Role, UserRole } from '@prisma/client';
import * as argon2 from 'argon2';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Starting SentinelFlow Phase 2 database seed with Auth & RBAC...');

  // 1. Create / Upsert Organizations
  const primaryOrg = await prisma.organization.upsert({
    where: { slug: 'cyberdefense-soc' },
    update: {},
    create: {
      id: 'org-cyberdefense-001',
      name: 'CyberDefense SOC Operations',
      slug: 'cyberdefense-soc',
    },
  });

  const secondaryOrg = await prisma.organization.upsert({
    where: { slug: 'secops-global' },
    update: {},
    create: {
      id: 'org-secops-002',
      name: 'SecOps Global Isolated Tenant',
      slug: 'secops-global',
    },
  });

  // 2. Hash Passwords using Argon2id
  const adminPasswordHash = await argon2.hash('AdminPassword123!', { type: argon2.argon2id });
  const analystPasswordHash = await argon2.hash('AnalystPassword123!', { type: argon2.argon2id });
  const viewerPasswordHash = await argon2.hash('ViewerPassword123!', { type: argon2.argon2id });
  const foreignPasswordHash = await argon2.hash('ForeignPassword123!', { type: argon2.argon2id });

  // 3. Create Users
  const admin = await prisma.user.upsert({
    where: { email: 'admin@sentinelflow.local' },
    update: { passwordHash: adminPasswordHash },
    create: {
      id: 'USR-ADMIN-001',
      email: 'admin@sentinelflow.local',
      name: 'Platform Administrator',
      passwordHash: adminPasswordHash,
      role: UserRole.ADMIN,
      tenantId: primaryOrg.id,
    },
  });

  const analyst = await prisma.user.upsert({
    where: { email: 'sarah.chen@sentinelflow.local' },
    update: { passwordHash: analystPasswordHash },
    create: {
      id: 'USR-SOC-001',
      email: 'sarah.chen@sentinelflow.local',
      name: 'Sarah Chen (Lead Analyst)',
      passwordHash: analystPasswordHash,
      role: UserRole.SOC_LEAD,
      tenantId: primaryOrg.id,
    },
  });

  const viewer = await prisma.user.upsert({
    where: { email: 'viewer@sentinelflow.local' },
    update: { passwordHash: viewerPasswordHash },
    create: {
      id: 'USR-VIEWER-001',
      email: 'viewer@sentinelflow.local',
      name: 'Auditor Viewer',
      passwordHash: viewerPasswordHash,
      role: UserRole.ANALYST,
      tenantId: primaryOrg.id,
    },
  });

  const foreignUser = await prisma.user.upsert({
    where: { email: 'foreign.user@secops.local' },
    update: { passwordHash: foreignPasswordHash },
    create: {
      id: 'USR-FOREIGN-001',
      email: 'foreign.user@secops.local',
      name: 'Foreign Org User',
      passwordHash: foreignPasswordHash,
      role: UserRole.ADMIN,
      tenantId: secondaryOrg.id,
    },
  });

  // 4. Create Organization Memberships
  await prisma.organizationMembership.upsert({
    where: { userId_organizationId: { userId: admin.id, organizationId: primaryOrg.id } },
    update: { role: Role.ADMIN },
    create: {
      userId: admin.id,
      organizationId: primaryOrg.id,
      role: Role.ADMIN,
    },
  });

  await prisma.organizationMembership.upsert({
    where: { userId_organizationId: { userId: analyst.id, organizationId: primaryOrg.id } },
    update: { role: Role.ANALYST },
    create: {
      userId: analyst.id,
      organizationId: primaryOrg.id,
      role: Role.ANALYST,
    },
  });

  await prisma.organizationMembership.upsert({
    where: { userId_organizationId: { userId: viewer.id, organizationId: primaryOrg.id } },
    update: { role: Role.VIEWER },
    create: {
      userId: viewer.id,
      organizationId: primaryOrg.id,
      role: Role.VIEWER,
    },
  });

  await prisma.organizationMembership.upsert({
    where: { userId_organizationId: { userId: foreignUser.id, organizationId: secondaryOrg.id } },
    update: { role: Role.ADMIN },
    create: {
      userId: foreignUser.id,
      organizationId: secondaryOrg.id,
      role: Role.ADMIN,
    },
  });

  // 5. Upsert Incidents for Primary Org
  const inc1 = await prisma.incident.upsert({
    where: { id: 'INC-2026-001' },
    update: { organizationId: primaryOrg.id },
    create: {
      id: 'INC-2026-001',
      title: 'Suspicious PowerShell Execution & EDR Evasion',
      description:
        'Endpoint telemetry flagged obfuscated PowerShell command executing base64 payload matching Mimikatz signatures on workstation WS-FIN-04.',
      severity: Severity.CRITICAL,
      status: IncidentStatus.INVESTIGATING,
      tenantId: primaryOrg.id,
      organizationId: primaryOrg.id,
      assignedToId: analyst.id,
      aiSummary: 'High-confidence credential dumping attempt following initial access via spear-phishing attachment.',
      aiRiskScore: 0.94,
      mitigationSteps: [
        'Isolate host WS-FIN-04 via EDR agent',
        'Revoke active Kerberos ticket-granting tickets for user j.doe',
        'Block egress communication to 198.51.100.42 at perimeter firewall',
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

  // Upsert Incident for Secondary (Foreign) Org to verify cross-tenant boundaries
  await prisma.incident.upsert({
    where: { id: 'INC-2026-FOREIGN' },
    update: { organizationId: secondaryOrg.id },
    create: {
      id: 'INC-2026-FOREIGN',
      title: 'Foreign Org Isolated Incident',
      description: 'Confidential security event restricted to SecOps Global.',
      severity: Severity.HIGH,
      status: IncidentStatus.NEW,
      tenantId: secondaryOrg.id,
      organizationId: secondaryOrg.id,
      assignedToId: foreignUser.id,
      createdAt: new Date(Date.now() - 1000000),
      updatedAt: new Date(Date.now() - 1000000),
    },
  });

  // 6. Upsert Alerts
  await prisma.securityAlert.upsert({
    where: { id: 'ALT-9821' },
    update: { organizationId: primaryOrg.id },
    create: {
      id: 'ALT-9821',
      title: 'PowerShell EncodedCommand Execution',
      description: 'Host WS-FIN-04 executed powershell.exe -enc with elevated permissions.',
      severity: Severity.CRITICAL,
      source: 'CrowdStrike Falcon EDR',
      incidentId: inc1.id,
      tenantId: primaryOrg.id,
      organizationId: primaryOrg.id,
      detectedAt: new Date(Date.now() - 3600000),
      createdAt: new Date(Date.now() - 3600000),
    },
  });

  await prisma.securityAlert.upsert({
    where: { id: 'ALT-FOREIGN-01' },
    update: { organizationId: secondaryOrg.id },
    create: {
      id: 'ALT-FOREIGN-01',
      title: 'Foreign Org Restricted Alert',
      description: 'Alert restricted to SecOps Global tenant.',
      severity: Severity.MEDIUM,
      source: 'SecOps Internal SIEM',
      tenantId: secondaryOrg.id,
      organizationId: secondaryOrg.id,
      detectedAt: new Date(Date.now() - 500000),
      createdAt: new Date(Date.now() - 500000),
    },
  });

  console.log('✅ SentinelFlow Phase 2 seed with Auth & RBAC completed successfully.');
}

main()
  .catch((e) => {
    console.error('❌ Error during seed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
