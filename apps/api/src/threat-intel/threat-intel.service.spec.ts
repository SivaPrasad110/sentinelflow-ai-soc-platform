import { Test, TestingModule } from '@nestjs/testing';
import { ThreatIntelService } from './threat-intel.service';
import { PrismaService } from '../prisma/prisma.service';
import { IocService } from '../ioc/ioc.service';
import { AuditService } from '../audit/audit.service';
import { EventsGateway } from '../events/events.gateway';

describe('ThreatIntelService (Phase 6 Threat Intelligence Feeds)', () => {
  let service: ThreatIntelService;
  let prismaMock: any;
  let iocService: IocService;
  let auditMock: any;
  let eventsMock: any;

  const orgId = 'org-sentinel-corp';

  beforeEach(async () => {
    prismaMock = {
      threatFeed: {
        count: jest.fn().mockResolvedValue(0),
        create: jest.fn().mockImplementation(({ data }) =>
          Promise.resolve({ id: 'feed-1', ...data, createdAt: new Date(), updatedAt: new Date() }),
        ),
        createMany: jest.fn().mockResolvedValue({ count: 3 }),
        findMany: jest.fn().mockResolvedValue([
          {
            id: 'feed-1',
            name: 'URLhaus Feed',
            feedUrl: 'https://urlhaus.abuse.ch/downloads/json_recent/',
            feedType: 'URLHAUS',
            format: 'JSON',
            organizationId: orgId,
            enabled: true,
            itemCount: 10,
            status: 'IDLE',
            createdAt: new Date(),
            updatedAt: new Date(),
          },
        ]),
        findFirst: jest.fn(),
        update: jest.fn().mockImplementation(({ data }) =>
          Promise.resolve({ id: 'feed-1', ...data, createdAt: new Date(), updatedAt: new Date() }),
        ),
      },
      indicatorOfCompromise: {
        count: jest.fn().mockResolvedValue(12),
        findFirst: jest.fn().mockResolvedValue(null),
        findMany: jest.fn().mockResolvedValue([
          { type: 'IP', severity: 'HIGH', isActive: true, mitreTechniques: ['T1071.001'] },
          { type: 'DOMAIN', severity: 'MEDIUM', isActive: true, mitreTechniques: ['T1071.001'] },
        ]),
        create: jest.fn().mockImplementation(({ data }) =>
          Promise.resolve({ id: 'ioc-created-1', ...data, createdAt: new Date(), updatedAt: new Date() }),
        ),
        update: jest.fn().mockImplementation(({ data }) =>
          Promise.resolve({ id: 'ioc-updated-1', ...data, createdAt: new Date(), updatedAt: new Date() }),
        ),
        groupBy: jest.fn().mockResolvedValue([
          { type: 'IP', _count: { id: 6 } },
          { type: 'DOMAIN', _count: { id: 4 } },
          { type: 'HASH_SHA256', _count: { id: 2 } },
        ]),
      },
      securityFinding: {
        count: jest.fn().mockResolvedValue(3),
        findMany: jest.fn().mockResolvedValue([]),
      },
      detectionRule: {
        findMany: jest.fn().mockResolvedValue([]),
      },
    };

    const iocMock = {
      validateIocFormat: jest.fn().mockReturnValue(true),
      create: jest.fn().mockResolvedValue({ id: 'ioc-created' }),
    };

    auditMock = {
      log: jest.fn().mockResolvedValue({}),
    };

    eventsMock = {
      broadcastToOrg: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ThreatIntelService,
        { provide: PrismaService, useValue: prismaMock },
        { provide: IocService, useValue: iocMock },
        { provide: AuditService, useValue: auditMock },
        { provide: EventsGateway, useValue: eventsMock },
      ],
    }).compile();

    service = module.get<ThreatIntelService>(ThreatIntelService);
    iocService = module.get<IocService>(IocService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('getFeeds', () => {
    it('should seed default feeds when feed count is 0', async () => {
      prismaMock.threatFeed.count.mockResolvedValue(0);

      const feeds = await service.getFeeds(orgId);

      expect(prismaMock.threatFeed.createMany).toHaveBeenCalled();
      expect(feeds).toBeDefined();
    });
  });

  describe('syncFeed', () => {
    it('should fall back to baseline indicators when external network feed fails', async () => {
      prismaMock.threatFeed.findFirst.mockResolvedValue({
        id: 'feed-urlhaus',
        name: 'Abuse.ch URLhaus (Malicious URLs)',
        feedUrl: 'https://urlhaus.abuse.ch/downloads/json_recent/',
        feedType: 'URLHAUS',
        format: 'JSON',
        organizationId: orgId,
        enabled: true,
        itemCount: 0,
        status: 'IDLE',
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      // Force fetch to fail (network error / offline sandbox)
      jest.spyOn(global, 'fetch').mockImplementation(() =>
        Promise.reject(new Error('Network offline in sandbox')),
      );

      const result = await service.syncFeed('feed-urlhaus', orgId);

      expect(result.status).toBe('SUCCESS'); // Clean fallback
      expect(result.indicatorsImported).toBeGreaterThan(0);
      expect(eventsMock.broadcastToOrg).toHaveBeenCalledWith(
        orgId,
        'feed:synced',
        expect.any(Object),
      );
    });
  });

  describe('getStats', () => {
    it('should return aggregated threat intelligence stats', async () => {
      prismaMock.threatFeed.count.mockResolvedValue(1);
      const stats = await service.getStats(orgId);

      expect(stats.totalIocs).toBe(2);
      expect(stats.feedCount).toBe(1);
      expect(stats.iocsByType).toBeDefined();
    });
  });
});
