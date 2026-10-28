import { Test, TestingModule } from '@nestjs/testing';
import { AlertsController } from './alerts.controller';
import { AlertsService } from './alerts.service';
import { PrismaService } from '../prisma/prisma.service';
import { NotFoundException, ForbiddenException } from '@nestjs/common';
import { Severity } from '@prisma/client';

describe('AlertsController & AlertsService', () => {
  let controller: AlertsController;
  let service: AlertsService;
  let prismaMock: any;

  const sampleAlert = {
    id: 'ALT-9821',
    title: 'PowerShell EncodedCommand Execution',
    description: 'Host WS-FIN-04 executed powershell.exe -enc with elevated permissions.',
    severity: Severity.CRITICAL,
    source: 'CrowdStrike Falcon EDR',
    tenantId: 'default-tenant',
    incidentId: 'INC-2026-001',
    rawPayload: { command: 'powershell.exe -enc ...' },
    detectedAt: new Date('2026-10-28T10:00:00Z'),
    createdAt: new Date('2026-10-28T10:00:00Z'),
  };

  beforeEach(async () => {
    prismaMock = {
      securityAlert: {
        findMany: jest.fn().mockResolvedValue([sampleAlert]),
        findFirst: jest.fn().mockImplementation(({ where }) => {
          if (where.id === sampleAlert.id && (!where.tenantId || where.tenantId === sampleAlert.tenantId)) {
            return Promise.resolve(sampleAlert);
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

  describe('Listing Alerts', () => {
    it('should list all alerts for default tenant', async () => {
      const alerts = await controller.findAll();
      expect(Array.isArray(alerts)).toBe(true);
      expect(alerts.length).toBe(1);
      expect(alerts[0].id).toBe('ALT-9821');
      expect(alerts[0].source).toBe('CrowdStrike Falcon EDR');
    });

    it('should reject unauthorized cross-tenant alert listing', async () => {
      await expect(controller.findAll('unauthorized-tenant')).rejects.toThrow(ForbiddenException);
    });
  });

  describe('Retrieving Alert by ID', () => {
    it('should retrieve existing alert', async () => {
      const alert = await controller.findById('ALT-9821');
      expect(alert).toBeDefined();
      expect(alert.id).toBe('ALT-9821');
    });

    it('should throw NotFoundException when alert does not exist', async () => {
      await expect(controller.findById('NON-EXISTENT-ALERT')).rejects.toThrow(NotFoundException);
    });
  });

  describe('Ingesting Alerts', () => {
    it('should ingest and persist a new alert', async () => {
      const dto = {
        title: 'New CloudTrail Root Login',
        description: 'ConsoleLogin from unauthorized country without MFA.',
        severity: Severity.HIGH,
        source: 'AWS GuardDuty',
      };

      const result = await controller.ingest(dto);
      expect(result).toBeDefined();
      expect(result.title).toBe(dto.title);
      expect(prismaMock.securityAlert.create).toHaveBeenCalled();
    });
  });

  describe('Updating Alerts', () => {
    it('should update existing alert', async () => {
      const result = await controller.update('ALT-9821', {
        severity: Severity.HIGH,
      });
      expect(result).toBeDefined();
      expect(prismaMock.securityAlert.update).toHaveBeenCalled();
    });

    it('should throw NotFoundException when updating non-existent alert', async () => {
      await expect(
        controller.update('NON-EXISTENT-ALERT', { severity: Severity.LOW }),
      ).rejects.toThrow(NotFoundException);
    });
  });
});
