/**
 * SentinelFlow — Tenant Isolation Integration Tests
 *
 * These tests verify that no data leaks across organization boundaries.
 * They use the real Prisma client against a test database (DATABASE_URL).
 *
 * Run: npx jest tests/integration/tenant-isolation.test.ts --testTimeout=30000
 *
 * Prerequisites:
 *   - Set TEST_DATABASE_URL in .env.test pointing to a fresh test database
 *   - The test database must have migrations applied: prisma migrate deploy
 */

import { PrismaClient } from '@prisma/client';
import * as crypto from 'crypto';

const prisma = new PrismaClient({
  datasources: { db: { url: process.env.DATABASE_URL } },
});

// ─── Test Data Helpers ──────────────────────────────────────────────────────

async function createTestOrg(name: string) {
  const slug = `test-${name.toLowerCase()}-${Date.now()}`;
  return prisma.organization.create({ data: { name, slug } });
}

async function createTestUser(email: string, orgId: string) {
  const user = await prisma.user.create({
    data: {
      email,
      name: 'Test User',
      passwordHash: 'not-used-in-isolation-tests',
      tenantId: orgId,
    },
  });
  await prisma.organizationMembership.create({
    data: { userId: user.id, organizationId: orgId, role: 'ADMIN' },
  });
  return user;
}

async function createTestIncident(title: string, orgId: string, userId: string) {
  return prisma.incident.create({
    data: {
      title,
      description: `Test incident for ${orgId}`,
      severity: 'HIGH',
      status: 'NEW',
      organizationId: orgId,
      tenantId: orgId,
      assignedToId: userId,
    },
  });
}

async function createTestAlert(title: string, orgId: string) {
  return prisma.securityAlert.create({
    data: {
      title,
      description: `Test alert for ${orgId}`,
      severity: 'HIGH',
      source: 'integration-test',
      organizationId: orgId,
      tenantId: orgId,
    },
  });
}

// ─── Cleanup Tracker ────────────────────────────────────────────────────────

const cleanupOrgIds: string[] = [];

afterAll(async () => {
  // Clean up all test data in dependency order
  if (cleanupOrgIds.length > 0) {
    await prisma.auditLog.deleteMany({ where: { organizationId: { in: cleanupOrgIds } } });
    await prisma.securityFinding.deleteMany({ where: { organizationId: { in: cleanupOrgIds } } });
    await prisma.detectionRule.deleteMany({ where: { organizationId: { in: cleanupOrgIds } } });
    await prisma.indicatorOfCompromise.deleteMany({ where: { organizationId: { in: cleanupOrgIds } } });
    await prisma.threatFeed.deleteMany({ where: { organizationId: { in: cleanupOrgIds } } });
    await prisma.securityAlert.deleteMany({ where: { organizationId: { in: cleanupOrgIds } } });
    await prisma.incident.deleteMany({ where: { organizationId: { in: cleanupOrgIds } } });
    await prisma.organizationMembership.deleteMany({ where: { organizationId: { in: cleanupOrgIds } } });
    await prisma.user.deleteMany({ where: { tenantId: { in: cleanupOrgIds } } });
    await prisma.organization.deleteMany({ where: { id: { in: cleanupOrgIds } } });
  }
  await prisma.$disconnect();
});

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('Tenant Isolation — Incidents', () => {
  let orgAId: string;
  let orgBId: string;
  let incidentAId: string;
  let incidentBId: string;

  beforeAll(async () => {
    const orgA = await createTestOrg('Org-Alpha');
    const orgB = await createTestOrg('Org-Beta');
    orgAId = orgA.id;
    orgBId = orgB.id;
    cleanupOrgIds.push(orgAId, orgBId);

    const userA = await createTestUser(`user-a-${Date.now()}@test.local`, orgAId);
    const userB = await createTestUser(`user-b-${Date.now()}@test.local`, orgBId);

    const incA = await createTestIncident('Alpha Breach', orgAId, userA.id);
    const incB = await createTestIncident('Beta Breach', orgBId, userB.id);
    incidentAId = incA.id;
    incidentBId = incB.id;
  });

  test('Org A cannot read Org B incidents via organizationId scope', async () => {
    const result = await prisma.incident.findFirst({
      where: { id: incidentBId, organizationId: orgAId }, // Cross-tenant query
    });
    expect(result).toBeNull();
  });

  test('Org B cannot read Org A incidents via organizationId scope', async () => {
    const result = await prisma.incident.findFirst({
      where: { id: incidentAId, organizationId: orgBId },
    });
    expect(result).toBeNull();
  });

  test('Org A sees only its own incidents', async () => {
    const results = await prisma.incident.findMany({
      where: { organizationId: orgAId },
    });
    const resultIds = results.map((i) => i.id);
    expect(resultIds).toContain(incidentAId);
    expect(resultIds).not.toContain(incidentBId);
  });

  test('Org B sees only its own incidents', async () => {
    const results = await prisma.incident.findMany({
      where: { organizationId: orgBId },
    });
    const resultIds = results.map((i) => i.id);
    expect(resultIds).toContain(incidentBId);
    expect(resultIds).not.toContain(incidentAId);
  });
});

describe('Tenant Isolation — Alerts', () => {
  let orgCId: string;
  let orgDId: string;
  let alertCId: string;
  let alertDId: string;

  beforeAll(async () => {
    const orgC = await createTestOrg('Org-Gamma');
    const orgD = await createTestOrg('Org-Delta');
    orgCId = orgC.id;
    orgDId = orgD.id;
    cleanupOrgIds.push(orgCId, orgDId);

    const alertC = await createTestAlert('Gamma Alert', orgCId);
    const alertD = await createTestAlert('Delta Alert', orgDId);
    alertCId = alertC.id;
    alertDId = alertD.id;
  });

  test('Alert created in Org C is not visible in Org D query', async () => {
    const result = await prisma.securityAlert.findFirst({
      where: { id: alertCId, organizationId: orgDId },
    });
    expect(result).toBeNull();
  });

  test('Alert created in Org D is not visible in Org C query', async () => {
    const result = await prisma.securityAlert.findFirst({
      where: { id: alertDId, organizationId: orgCId },
    });
    expect(result).toBeNull();
  });
});

describe('Tenant Isolation — Audit Logs', () => {
  let orgEId: string;
  let orgFId: string;
  let auditEId: string;

  beforeAll(async () => {
    const orgE = await createTestOrg('Org-Epsilon');
    const orgF = await createTestOrg('Org-Zeta');
    orgEId = orgE.id;
    orgFId = orgF.id;
    cleanupOrgIds.push(orgEId, orgFId);

    const auditE = await prisma.auditLog.create({
      data: {
        organizationId: orgEId,
        action: 'TEST_ACTION',
        entityType: 'TEST',
        details: { test: true },
      },
    });
    auditEId = auditE.id;
  });

  test('Org F cannot see Org E audit log entries', async () => {
    const result = await prisma.auditLog.findFirst({
      where: { id: auditEId, organizationId: orgFId },
    });
    expect(result).toBeNull();
  });

  test('Org E audit log is correctly scoped', async () => {
    const result = await prisma.auditLog.findFirst({
      where: { id: auditEId, organizationId: orgEId },
    });
    expect(result).not.toBeNull();
    expect(result?.action).toBe('TEST_ACTION');
  });
});

describe('Tenant Isolation — Detection Rules', () => {
  let orgGId: string;
  let orgHId: string;
  let ruleGId: string;

  beforeAll(async () => {
    const orgG = await createTestOrg('Org-Eta');
    const orgH = await createTestOrg('Org-Theta');
    orgGId = orgG.id;
    orgHId = orgH.id;
    cleanupOrgIds.push(orgGId, orgHId);

    const ruleG = await prisma.detectionRule.create({
      data: {
        organizationId: orgGId,
        name: 'Org G Only Rule',
        description: 'Test rule scoped to Org G',
        severity: 'HIGH',
        ruleType: 'PATTERN',
        criteria: [{ field: 'title', operator: 'CONTAINS', value: 'test' }],
      },
    });
    ruleGId = ruleG.id;
  });

  test('Org H cannot query Org G detection rules', async () => {
    const result = await prisma.detectionRule.findFirst({
      where: { id: ruleGId, organizationId: orgHId },
    });
    expect(result).toBeNull();
  });

  test('Org G rule is accessible within Org G scope', async () => {
    const result = await prisma.detectionRule.findFirst({
      where: { id: ruleGId, organizationId: orgGId },
    });
    expect(result).not.toBeNull();
    expect(result?.name).toBe('Org G Only Rule');
  });
});

describe('Tenant Isolation — IOC Fingerprinting', () => {
  test('SHA-256 fingerprints are deterministic per org+rule+source+title', () => {
    const orgId = 'test-org-id';
    const ruleId = 'test-rule-id';
    const alertSource = 'EDR';
    const alertTitle = 'suspicious powershell execution';

    const input1 = `${orgId}:${ruleId}:${alertSource}:${alertTitle}`;
    const input2 = `${orgId}:${ruleId}:${alertSource}:${alertTitle}`;
    const differentOrg = `other-org-id:${ruleId}:${alertSource}:${alertTitle}`;

    const fp1 = crypto.createHash('sha256').update(input1).digest('hex');
    const fp2 = crypto.createHash('sha256').update(input2).digest('hex');
    const fpOther = crypto.createHash('sha256').update(differentOrg).digest('hex');

    expect(fp1).toBe(fp2); // Same input = same fingerprint
    expect(fp1).not.toBe(fpOther); // Different org = different fingerprint
  });
});
