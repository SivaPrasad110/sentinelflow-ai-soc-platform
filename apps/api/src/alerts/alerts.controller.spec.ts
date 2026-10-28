import { Test, TestingModule } from '@nestjs/testing';
import { AlertsController } from './alerts.controller';
import { AlertsService } from './alerts.service';
import { PrismaService } from '../prisma/prisma.service';
import { NotFoundException } from '@nestjs/common';
import { Severity } from '@prisma/client';

describe('AlertsController & AlertsService (Scoped Multi-Tenancy)', () => {
  let controller: AlertsController;
  let service: AlertsService;
  let prismaMock: any;

  const currentOrgId = 'org-cyberdefense-001';
  const foreignOrgId = 'org-secops-002';

  const sampleAlert = {
    id: 'ALT-9821',
    title: 'PowerShell EncodedCommand Execution',
    description: 'Host WS-FIN-04 executed powershell.exe -enc with elevated permissions.',
    severity: Severity.CRITICAL,
    source: 'CrowdStrike Falcon EDR',
    organizationId: currentOrgId,
    tenantId: currentOrgId,
    incidentId: 'INC-2026-001',
    rawPayload: { command: 'powershell.exe -enc ...' },
    detectedAt: new Date('2026-10-28T10:00:00Z'),
    createdAt: new Date('2026-10-28T10:00:00Z'),
  };

  const foreignAlert = {
    ...sampleAlert,
    id: 'ALT-FOREIGN-01',
    organizationId: foreignOrgId,
    tenantId: foreignOrgId,
    title: 'Foreign Org Restricted Alert',
  };

  beforeEach(async () => {
    prismaMock = {
      securityAlert: {
        findMany: jest.fn().mockImplementation(({ where }) => {
          const targetOrg = where.OR?.[0]?.organizationId;
          if (targetOrg === currentOrgId) {
            return Promise.resolve([sampleAlert]);
          }
          if (targetOrg === foreignOrgId) {
            return Promise.resolve([foreignAlert]);
          }
          return Promise.resolve([]);
        }),
        findFirst: jest.fn().mockImplementation(({ where }) => {
          const targetOrg = where.OR?.[0]?.organizationId;
          if (where.id === sampleAlert.id && targetOrg === currentOrgId) {
            return Promise.resolve(sampleAlert);
          }
          if (where.id === foreignAlert.id && targetOrg === foreignOrgId) {
            return Promise.resolve(foreignAlert);
          }
          return Promise.resolve(null);
        }),
        create: jest.fn().mockImplementation(({ data }) => {
          return Promise.resolve({
            ...sampleAlert,
            ...data,
            id: 'ALT-9999',
            createdAt: new Date(),
          });
        }),
        update: jest.fn().mockImplementation(({ where, data }) => {
          return Promise.resolve({
            ...sampleAlert,
            ...data,
            id: where.id,
          });
        }),
      },
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AlertsController],
      providers: [
        AlertsService,
        {
          provide: PrismaService,
          useValue: prismaMock,
        },
      ],
    }).compile();

    controller = module.get<AlertsController>(AlertsController);
    service = module.get<AlertsService>(AlertsService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
    expect(service).toBeDefined();
  });

  describe('Listing Alerts in Organization', () => {
    it('should list all alerts scoped strictly to authorized organization', async () => {
      const alerts = await controller.findAll(currentOrgId);
      expect(Array.isArray(alerts)).toBe(true);
      expect(alerts.length).toBe(1);
      expect(alerts[0].id).toBe('ALT-9821');
      expect(alerts[0].organizationId).toBe(currentOrgId);
    });
  });

  describe('Cross-Tenant Alert IDOR Prevention', () => {
    it('should retrieve alert within authorized organization', async () => {
      const alert = await controller.findById('ALT-9821', currentOrgId);
      expect(alert).toBeDefined();
      expect(alert.id).toBe('ALT-9821');
    });

    it('should prevent cross-tenant access to foreign organization alert', async () => {
      await expect(
        controller.findById('ALT-FOREIGN-01', currentOrgId),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('Ingesting & Updating Alerts (Permitted Analyst Actions)', () => {
    it('should ingest and persist a new alert under authorized organization', async () => {
      const dto = {
        title: 'New CloudTrail Root Login',
        description: 'ConsoleLogin from unrecognized IP.',
        severity: Severity.HIGH,
        source: 'AWS GuardDuty',
      };

      const result = await controller.ingest(dto, currentOrgId);
      expect(result).toBeDefined();
      expect(prismaMock.securityAlert.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            organizationId: currentOrgId,
          }),
        }),
      );
    });

    it('should update an alert within authorized organization', async () => {
      const result = await controller.update('ALT-9821', { severity: Severity.HIGH }, currentOrgId);
      expect(result).toBeDefined();
      expect(prismaMock.securityAlert.update).toHaveBeenCalled();
    });
  });
});
