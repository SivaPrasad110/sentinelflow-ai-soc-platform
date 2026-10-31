import { Test, TestingModule } from '@nestjs/testing';
import { AnalyticsService } from './analytics.service';
import { PrismaService } from '../prisma/prisma.service';

describe('AnalyticsService (Phase 5 SOC Monitoring)', () => {
  let service: AnalyticsService;
  let prismaMock: any;

  const currentOrgId = 'org-sentinel-corp';

  beforeEach(async () => {
    prismaMock = {
      incident: {
        findMany: jest.fn().mockResolvedValue([
          {
            id: 'INC-001',
            organizationId: currentOrgId,
            severity: 'CRITICAL',
            status: 'RESOLVED',
            assignedToId: 'usr-1',
            assignedTo: { id: 'usr-1', name: 'Sarah Chen' },
            createdAt: new Date('2026-10-31T10:00:00Z'),
            acknowledgedAt: new Date('2026-10-31T10:10:00Z'), // 10 minutes
            resolvedAt: new Date('2026-10-31T10:40:00Z'), // 40 minutes
          },
          {
            id: 'INC-002',
            organizationId: currentOrgId,
            severity: 'HIGH',
            status: 'INVESTIGATING',
            assignedToId: 'usr-1',
            assignedTo: { id: 'usr-1', name: 'Sarah Chen' },
            createdAt: new Date('2026-10-31T11:00:00Z'),
            acknowledgedAt: new Date('2026-10-31T11:20:00Z'), // 20 minutes
            resolvedAt: null,
          },
        ]),
      },
      securityAlert: {
        count: jest.fn().mockResolvedValue(2),
        findMany: jest.fn().mockResolvedValue([
          {
            id: 'ALT-001',
            organizationId: currentOrgId,
            severity: 'CRITICAL',
            detectedAt: new Date('2026-10-31T09:00:00Z'),
          },
          {
            id: 'ALT-002',
            organizationId: currentOrgId,
            severity: 'HIGH',
            detectedAt: new Date('2026-10-31T09:30:00Z'),
          },
        ]),
      },
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AnalyticsService,
        {
          provide: PrismaService,
          useValue: prismaMock,
        },
      ],
    }).compile();

    service = module.get<AnalyticsService>(AnalyticsService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('getSocMetrics', () => {
    it('should accurately calculate MTTA and MTTR in minutes', async () => {
      const metrics = await service.getSocMetrics(currentOrgId);

      expect(metrics).toBeDefined();
      expect(metrics.overview.totalIncidents).toBe(2);
      expect(metrics.overview.openIncidents).toBe(1);
      expect(metrics.overview.resolvedIncidents).toBe(1);
      expect(metrics.overview.activeAlertsCount).toBe(2);
      expect(metrics.overview.criticalIncidentsCount).toBe(1);

      // (10m + 20m) / 2 = 15m
      expect(metrics.overview.meanTimeToAcknowledgeMinutes).toBe(15);
      // 40m / 1 = 40m
      expect(metrics.overview.meanTimeToResolveMinutes).toBe(40);
    });

    it('should aggregate severity and status distribution', async () => {
      const metrics = await service.getSocMetrics(currentOrgId);

      expect(metrics.severityDistribution.CRITICAL).toBe(1);
      expect(metrics.severityDistribution.HIGH).toBe(1);
      expect(metrics.severityDistribution.MEDIUM).toBe(0);
      expect(metrics.severityDistribution.LOW).toBe(0);

      expect(metrics.statusDistribution.RESOLVED).toBe(1);
      expect(metrics.statusDistribution.INVESTIGATING).toBe(1);
      expect(metrics.statusDistribution.NEW).toBe(0);
    });

    it('should compute analyst workload distribution', async () => {
      const metrics = await service.getSocMetrics(currentOrgId);

      expect(Array.isArray(metrics.analystWorkload)).toBe(true);
      expect(metrics.analystWorkload.length).toBe(1);
      expect(metrics.analystWorkload[0]).toEqual({
        analystId: 'usr-1',
        analystName: 'Sarah Chen',
        assignedCount: 1,
      });
    });

    it('should isolate queries strictly to the requested organization', async () => {
      await service.getSocMetrics(currentOrgId);

      expect(prismaMock.incident.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            OR: [
              { organizationId: currentOrgId },
              { tenantId: currentOrgId },
            ],
          }),
        }),
      );
      expect(prismaMock.securityAlert.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            OR: [
              { organizationId: currentOrgId },
              { tenantId: currentOrgId },
            ],
          }),
        }),
      );
    });
  });
});
