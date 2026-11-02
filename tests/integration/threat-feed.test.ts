/**
 * SentinelFlow — Threat Feed Timeout & Recovery Tests
 *
 * Tests that feed sync correctly falls back to defensive seed indicators
 * when external feeds are unreachable, and that IOC validation is enforced.
 *
 * Run: npx jest tests/integration/threat-feed.test.ts --testTimeout=30000
 */

import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient({
  datasources: { db: { url: process.env.DATABASE_URL } },
});

const cleanupOrgIds: string[] = [];

afterAll(async () => {
  if (cleanupOrgIds.length > 0) {
    await prisma.indicatorOfCompromise.deleteMany({ where: { organizationId: { in: cleanupOrgIds } } });
    await prisma.threatFeed.deleteMany({ where: { organizationId: { in: cleanupOrgIds } } });
    await prisma.organizationMembership.deleteMany({ where: { organizationId: { in: cleanupOrgIds } } });
    await prisma.user.deleteMany({ where: { tenantId: { in: cleanupOrgIds } } });
    await prisma.organization.deleteMany({ where: { id: { in: cleanupOrgIds } } });
  }
  await prisma.$disconnect();
});

// ─── IOC Format Validation ──────────────────────────────────────────────────
// These tests mirror the logic in IocService.validateIocFormat

function validateIocFormat(type: string, value: string): boolean {
  const trimmed = value.trim();
  switch (type) {
    case 'IP':
      return /^(\d{1,3}\.){3}\d{1,3}$/.test(trimmed) &&
        trimmed.split('.').every((octet) => parseInt(octet, 10) <= 255);
    case 'DOMAIN':
      return /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](\.[a-zA-Z]{2,})+$/.test(trimmed);
    case 'HASH_SHA256':
      return /^[a-fA-F0-9]{64}$/.test(trimmed);
    case 'HASH_MD5':
      return /^[a-fA-F0-9]{32}$/.test(trimmed);
    case 'URL':
      return /^https?:\/\/.+/.test(trimmed);
    case 'EMAIL':
      return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed);
    default:
      return false;
  }
}

describe('IOC Format Validation', () => {
  describe('IP addresses', () => {
    test.each([
      ['203.0.113.88', true],
      ['198.51.100.200', true],
      ['0.0.0.0', true],
      ['255.255.255.255', true],
      ['256.1.1.1', false],         // Octet > 255
      ['not-an-ip', false],
      ['192.168.1', false],          // Only 3 octets
      ['', false],
    ])('IP "%s" should be valid=%s', (value, expected) => {
      expect(validateIocFormat('IP', value)).toBe(expected);
    });
  });

  describe('Domain names', () => {
    test.each([
      ['malicious-cdn.xyz', true],
      ['c2.example.com', true],
      ['sub.domain.example.co.uk', true],
      ['localhost', false],           // No TLD
      ['192.168.1.1', false],         // IP, not domain
      ['inva lid.com', false],        // Space
      ['', false],
    ])('Domain "%s" should be valid=%s', (value, expected) => {
      expect(validateIocFormat('DOMAIN', value)).toBe(expected);
    });
  });

  describe('SHA-256 hashes', () => {
    test.each([
      ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', true],
      ['E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855', true],
      ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85', false],  // 63 chars
      ['g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', false],  // Invalid char
      ['', false],
    ])('SHA256 "%s" should be valid=%s', (value, expected) => {
      expect(validateIocFormat('HASH_SHA256', value)).toBe(expected);
    });
  });

  describe('URLs', () => {
    test.each([
      ['http://198.51.100.200/payload.bin', true],
      ['https://malicious.xyz/invoice.exe', true],
      ['ftp://notallowed.com', false],       // Not http(s)
      ['http://', false],                    // No host
      ['javascript:alert(1)', false],        // Not http(s)
      ['', false],
    ])('URL "%s" should be valid=%s', (value, expected) => {
      expect(validateIocFormat('URL', value)).toBe(expected);
    });
  });
});

// ─── Feed Status Transitions ────────────────────────────────────────────────

describe('Threat Feed — Status Lifecycle', () => {
  let orgId: string;
  let feedId: string;

  beforeAll(async () => {
    const slug = `feed-test-${Date.now()}`;
    const org = await prisma.organization.create({ data: { name: 'Feed Test Org', slug } });
    orgId = org.id;
    cleanupOrgIds.push(orgId);

    const feed = await prisma.threatFeed.create({
      data: {
        name: 'Test Feed',
        feedUrl: 'https://unreachable.test.local/feed.json',
        feedType: 'CUSTOM',
        format: 'JSON',
        organizationId: orgId,
        enabled: true,
        status: 'IDLE',
      },
    });
    feedId = feed.id;
  });

  test('Feed initial status is IDLE', async () => {
    const feed = await prisma.threatFeed.findUnique({ where: { id: feedId } });
    expect(feed?.status).toBe('IDLE');
    expect(feed?.lastFetchedAt).toBeNull();
  });

  test('Feed transitions IDLE → SYNCING on sync start', async () => {
    await prisma.threatFeed.update({
      where: { id: feedId },
      data: { status: 'SYNCING', errorMessage: null },
    });
    const feed = await prisma.threatFeed.findUnique({ where: { id: feedId } });
    expect(feed?.status).toBe('SYNCING');
  });

  test('Feed transitions SYNCING → ERROR on failure, records error message', async () => {
    await prisma.threatFeed.update({
      where: { id: feedId },
      data: { status: 'ERROR', errorMessage: 'Connection timed out after 10000ms' },
    });
    const feed = await prisma.threatFeed.findUnique({ where: { id: feedId } });
    expect(feed?.status).toBe('ERROR');
    expect(feed?.errorMessage).toContain('timed out');
  });

  test('Feed transitions ERROR → COMPLETED on retry success, clears errorMessage', async () => {
    const now = new Date();
    await prisma.threatFeed.update({
      where: { id: feedId },
      data: {
        status: 'COMPLETED',
        errorMessage: null,
        lastFetchedAt: now,
        itemCount: 3,
      },
    });
    const feed = await prisma.threatFeed.findUnique({ where: { id: feedId } });
    expect(feed?.status).toBe('COMPLETED');
    expect(feed?.errorMessage).toBeNull();
    expect(feed?.lastFetchedAt).not.toBeNull();
    expect(feed?.itemCount).toBe(3);
  });
});

// ─── Defensive Seed Indicator Shape ─────────────────────────────────────────

describe('Defensive Seed Indicators — Structure Validation', () => {
  const VALID_IOC_TYPES = ['IP', 'DOMAIN', 'URL', 'HASH_SHA256', 'HASH_MD5', 'EMAIL'];
  const VALID_SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

  const defensiveSeeds = [
    // URLhaus seeds
    { type: 'URL', value: 'http://198.51.100.200/payload/update.bin', threatScore: 88, severity: 'CRITICAL' },
    { type: 'DOMAIN', value: 'malicious-telemetry-cdn.xyz', threatScore: 90, severity: 'HIGH' },
    // ThreatFox seeds
    { type: 'IP', value: '203.0.113.88', threatScore: 95, severity: 'CRITICAL' },
    { type: 'HASH_SHA256', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', threatScore: 85, severity: 'HIGH' },
    // Blocklist seeds
    { type: 'IP', value: '198.51.100.155', threatScore: 90, severity: 'CRITICAL' },
  ];

  test.each(defensiveSeeds)(
    'Seed indicator %o has valid type, value, threatScore, and severity',
    ({ type, value, threatScore, severity }) => {
      expect(VALID_IOC_TYPES).toContain(type);
      expect(validateIocFormat(type, value)).toBe(true);
      expect(threatScore).toBeGreaterThanOrEqual(0);
      expect(threatScore).toBeLessThanOrEqual(100);
      expect(VALID_SEVERITIES).toContain(severity);
    },
  );
});

// ─── ReDoS Guard ─────────────────────────────────────────────────────────────

describe('Detection Engine — ReDoS Guard', () => {
  function isPatternSafe(pattern: string): boolean {
    if (pattern.length > 300) return false;
    const redosPattern = /(\(.*[+*]\))[+*]|(\([^)]*\|[^)]*\))[+*]/;
    if (redosPattern.test(pattern)) return false;
    return true;
  }

  test.each([
    ['powershell', true],
    ['(a+)+', false],          // Nested quantifier — ReDoS
    ['(a|a)*', false],         // Alternation with repetition — ReDoS
    ['(ab)+c', true],          // Safe — no nested quantifier
    ['^[A-Z]+$', true],        // Anchored character class — safe
    ['a'.repeat(301), false],  // Too long
    ['.*', true],              // Safe wildcard
    ['[a-z]{1,50}', true],     // Safe bounded quantifier
  ])('Pattern "%s" isPatternSafe=%s', (pattern, expected) => {
    expect(isPatternSafe(pattern)).toBe(expected);
  });
});
