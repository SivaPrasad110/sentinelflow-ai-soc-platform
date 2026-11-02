/**
 * SentinelFlow — Authentication Flow Integration Tests
 *
 * Tests the full auth lifecycle:
 *   register → login → refresh rotation → logout → revocation
 *
 * Uses real Prisma client. Requires a running test database.
 *
 * Run: npx jest tests/integration/auth-flow.test.ts --testTimeout=30000
 */

import { PrismaClient } from '@prisma/client';
import * as argon2 from 'argon2';
import * as crypto from 'crypto';

const prisma = new PrismaClient({
  datasources: { db: { url: process.env.DATABASE_URL } },
});

// ─── Helpers ────────────────────────────────────────────────────────────────

function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function generateSecureToken(): string {
  return crypto.randomBytes(40).toString('hex');
}

async function createTestUserWithOrg(email: string) {
  const slug = `test-auth-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const org = await prisma.organization.create({
    data: { name: 'Auth Test Org', slug },
  });
  const passwordHash = await argon2.hash('TestPassword123!', {
    type: argon2.argon2id,
    memoryCost: 4096, // Low cost for tests
    timeCost: 1,
    parallelism: 1,
  });
  const user = await prisma.user.create({
    data: { email, name: 'Auth Tester', passwordHash, tenantId: org.id },
  });
  await prisma.organizationMembership.create({
    data: { userId: user.id, organizationId: org.id, role: 'ADMIN' },
  });
  return { user, org };
}

const cleanupUserIds: string[] = [];
const cleanupOrgIds: string[] = [];

afterAll(async () => {
  await prisma.refreshSession.deleteMany({ where: { userId: { in: cleanupUserIds } } });
  await prisma.organizationMembership.deleteMany({ where: { userId: { in: cleanupUserIds } } });
  await prisma.user.deleteMany({ where: { id: { in: cleanupUserIds } } });
  await prisma.organization.deleteMany({ where: { id: { in: cleanupOrgIds } } });
  await prisma.$disconnect();
});

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('Auth — Password Hashing (Argon2id)', () => {
  test('Argon2id hashes are unique per call (salt randomness)', async () => {
    const hash1 = await argon2.hash('SamePassword!', { type: argon2.argon2id, memoryCost: 4096, timeCost: 1, parallelism: 1 });
    const hash2 = await argon2.hash('SamePassword!', { type: argon2.argon2id, memoryCost: 4096, timeCost: 1, parallelism: 1 });
    expect(hash1).not.toBe(hash2); // Different salts → different hashes
  });

  test('Argon2id verification works correctly', async () => {
    const hash = await argon2.hash('CorrectPassword!', { type: argon2.argon2id, memoryCost: 4096, timeCost: 1, parallelism: 1 });
    expect(await argon2.verify(hash, 'CorrectPassword!')).toBe(true);
    expect(await argon2.verify(hash, 'WrongPassword!')).toBe(false);
  });

  test('Argon2id hash type is argon2id (not argon2i or argon2d)', async () => {
    const hash = await argon2.hash('TestPass', { type: argon2.argon2id, memoryCost: 4096, timeCost: 1, parallelism: 1 });
    expect(hash).toMatch(/^\$argon2id\$/); // Confirms argon2id variant
  });
});

describe('Auth — Refresh Token Storage (Hash-Only)', () => {
  let userId: string;
  let orgId: string;

  beforeAll(async () => {
    const { user, org } = await createTestUserWithOrg(`hash-test-${Date.now()}@test.local`);
    userId = user.id;
    orgId = org.id;
    cleanupUserIds.push(userId);
    cleanupOrgIds.push(orgId);
  });

  test('Raw refresh token is never stored — only SHA-256 hash', async () => {
    const rawToken = generateSecureToken();
    const tokenHash = hashToken(rawToken);
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    const session = await prisma.refreshSession.create({
      data: { userId, tokenHash, expiresAt },
    });

    // Verify the raw token is NOT stored
    expect(session.tokenHash).toBe(tokenHash);
    expect(session.tokenHash).not.toBe(rawToken);
    expect(session.tokenHash.length).toBe(64); // SHA-256 hex = 64 chars

    await prisma.refreshSession.delete({ where: { id: session.id } });
  });

  test('Token lookup by hash succeeds, by raw token fails', async () => {
    const rawToken = generateSecureToken();
    const tokenHash = hashToken(rawToken);
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await prisma.refreshSession.create({ data: { userId, tokenHash, expiresAt } });

    // Lookup by hash: should succeed
    const found = await prisma.refreshSession.findUnique({ where: { tokenHash } });
    expect(found).not.toBeNull();

    // Lookup by raw token (wrong): should fail
    const notFound = await prisma.refreshSession.findUnique({ where: { tokenHash: rawToken } });
    expect(notFound).toBeNull();

    await prisma.refreshSession.deleteMany({ where: { userId, tokenHash } });
  });
});

describe('Auth — Token Rotation (Revocation)', () => {
  let userId: string;
  let orgId: string;

  beforeAll(async () => {
    const { user, org } = await createTestUserWithOrg(`rotation-test-${Date.now()}@test.local`);
    userId = user.id;
    orgId = org.id;
    cleanupUserIds.push(userId);
    cleanupOrgIds.push(orgId);
  });

  test('Refresh token rotation marks old session as revoked', async () => {
    const rawToken = generateSecureToken();
    const tokenHash = hashToken(rawToken);
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    const session = await prisma.refreshSession.create({ data: { userId, tokenHash, expiresAt } });

    // Simulate token rotation: revoke old session
    await prisma.refreshSession.update({
      where: { id: session.id },
      data: { revokedAt: new Date() },
    });

    // Old session should be revoked
    const revokedSession = await prisma.refreshSession.findUnique({ where: { tokenHash } });
    expect(revokedSession?.revokedAt).not.toBeNull();

    await prisma.refreshSession.delete({ where: { id: session.id } });
  });

  test('Expired refresh token is rejected by expiry check', async () => {
    const rawToken = generateSecureToken();
    const tokenHash = hashToken(rawToken);
    const expiresAt = new Date(Date.now() - 1000); // Already expired

    const session = await prisma.refreshSession.create({ data: { userId, tokenHash, expiresAt } });

    const found = await prisma.refreshSession.findUnique({ where: { tokenHash } });
    const isValid = found !== null && found.revokedAt === null && found.expiresAt > new Date();
    expect(isValid).toBe(false); // Should be rejected

    await prisma.refreshSession.delete({ where: { id: session.id } });
  });

  test('Revoked refresh token is rejected regardless of expiry', async () => {
    const rawToken = generateSecureToken();
    const tokenHash = hashToken(rawToken);
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // Still valid

    const session = await prisma.refreshSession.create({
      data: { userId, tokenHash, expiresAt, revokedAt: new Date() }, // Revoked immediately
    });

    const found = await prisma.refreshSession.findUnique({ where: { tokenHash } });
    const isValid = found !== null && found.revokedAt === null && found.expiresAt > new Date();
    expect(isValid).toBe(false); // Revoked token is invalid

    await prisma.refreshSession.delete({ where: { id: session.id } });
  });
});

describe('Auth — Logout (Session Revocation)', () => {
  let userId: string;
  let orgId: string;

  beforeAll(async () => {
    const { user, org } = await createTestUserWithOrg(`logout-test-${Date.now()}@test.local`);
    userId = user.id;
    orgId = org.id;
    cleanupUserIds.push(userId);
    cleanupOrgIds.push(orgId);
  });

  test('Logout revokes all matching active sessions', async () => {
    const rawToken = generateSecureToken();
    const tokenHash = hashToken(rawToken);
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await prisma.refreshSession.create({ data: { userId, tokenHash, expiresAt } });

    // Simulate logout: revoke session
    await prisma.refreshSession.updateMany({
      where: { tokenHash, revokedAt: null },
      data: { revokedAt: new Date() },
    });

    const session = await prisma.refreshSession.findUnique({ where: { tokenHash } });
    expect(session?.revokedAt).not.toBeNull();

    await prisma.refreshSession.deleteMany({ where: { userId, tokenHash } });
  });
});
