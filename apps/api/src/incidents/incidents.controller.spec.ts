import { Test, TestingModule } from '@nestjs/testing';
import { IncidentsController } from './incidents.controller';
import { IncidentsService } from './incidents.service';
import { PrismaService } from '../prisma/prisma.service';
import { NotFoundException, ForbiddenException } from '@nestjs/common';
import { Severity, IncidentStatus } from '@prisma/client';

describe('IncidentsController & IncidentsService', () => {
  let controller: IncidentsController;
  let service: IncidentsService;
  let prismaMock: any;

  const sampleIncident = {
    id: 'INC-2026-001',
    title: 'Suspicious PowerShell Execution',
    description: 'Obfuscated command line detected on endpoint.',
    severity: Severity.CRITICAL,
    status: IncidentStatus.INVESTIGATING,
    tenantId: 'default-tenant',
    assignedToId: 'USR-SOC-001',
    aiSummary: 'Likely credential access.',
    aiRiskScore: 0.92,
    mitigationSteps: ['Isolate host'],
    aiAnalysis: { summary: 'Likely credential access', confidenceScore: 0.92 },
    createdAt: new Date('2026-10-28T10:00:00Z'),
    updatedAt: new Date('2026-10-28T10:30:00Z'),
    iocs: [
      {
        id: 'IOC-001',
        type: 'IP',
        value: '198.51.100.42',
        threatScore: 89,
        enrichedData: null,
        incidentId: 'INC-2026-001',
        createdAt: new Date('2026-10-28T10:00:00Z'),
      },
    ],
    alerts: [],
    assignedTo: {
      id: 'USR-SOC-001',
      name: 'Sarah Chen',
      email: 'sarah.chen@sentinelflow.local',
    },
  };

  beforeEach(async () => {
    prismaMock = {
      incident: {
        findMany: jest.fn().mockResolvedValue([sampleIncident]),
        findFirst: jest.fn().mockImplementation(({ where }) => {
          if (where.id === sampleIncident.id && (!where.tenantId || where.tenantId === sampleIncident.tenantId)) {
            return Promise.resolve(sampleIncident);
          }
          return Promise.resolve(null);
        }),
        create: jest.fn().mockImplementation(({ data }) => {
          return Promise.resolve({
            ...sampleIncident,
            ...data,
            id: 'INC-2026-999',
            createdAt: new Date(),
            updatedAt: new Date(),
          });
        }),
        update: jest.fn().mockImplementation(({ where, data }) => {
          return Promise.resolve({
            ...sampleIncident,
            ...data,
            id: where.id,
            updatedAt: new Date(),
          });
        }),
        delete: jest.fn().mockResolvedValue(sampleIncident),
      },
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [IncidentsController],
      providers: [
        IncidentsService,
        {
          provide: PrismaService,
          useValue: prismaMock,
        },
      ],
    }).compile();

    controller = module.get<IncidentsController>(IncidentsController);
    service = module.get<IncidentsService>(IncidentsService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
    expect(service).toBeDefined();
  });

  describe('Listing Incidents', () => {
    it('should list all incidents for default tenant', async () => {
      const incidents = await controller.findAll();
      expect(Array.isArray(incidents)).toBe(true);
      expect(incidents.length).toBe(1);
      expect(incidents[0].id).toBe('INC-2026-001');
      expect(incidents[0].assignedTo).toBe('Sarah Chen');
      expect(incidents[0].iocs.length).toBe(1);
    });

    it('should reject unauthorized cross-tenant access', async () => {
      await expect(controller.findAll('unauthorized-foreign-tenant')).rejects.toThrow(
        ForbiddenException,
      );
    });
  });

  describe('Retrieving Incident by ID', () => {
    it('should retrieve existing incident', async () => {
      const result = await controller.findById('INC-2026-001');
      expect(result).toBeDefined();
      expect(result.id).toBe('INC-2026-001');
      expect(result.severity).toBe('CRITICAL');
    });

    it('should throw NotFoundException when incident does not exist', async () => {
      await expect(controller.findById('NON-EXISTENT-ID')).rejects.toThrow(NotFoundException);
    });
  });

  describe('Creating Incidents', () => {
    it('should create and persist a new incident', async () => {
      const dto = {
        title: 'New Ransomware Attempt',
        description: 'VSS shadow copy deletion detected.',
        severity: Severity.CRITICAL,
        status: IncidentStatus.NEW,
        mitigationSteps: ['Terminate malicious process tree'],
      };

      const created = await controller.create(dto);
      expect(created).toBeDefined();
      expect(created.title).toBe(dto.title);
      expect(prismaMock.incident.create).toHaveBeenCalled();
    });
  });

  describe('Updating Incidents', () => {
    it('should update status and severity of an existing incident', async () => {
      const updateDto = {
        status: IncidentStatus.CONTAINED,
        severity: Severity.HIGH,
      };

      const updated = await controller.update('INC-2026-001', updateDto);
      expect(updated).toBeDefined();
      expect(updated.status).toBe(IncidentStatus.CONTAINED);
      expect(prismaMock.incident.update).toHaveBeenCalled();
    });

    it('should throw NotFoundException when updating non-existent incident', async () => {
      await expect(
        controller.update('NON-EXISTENT-ID', { status: IncidentStatus.CLOSED }),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('Deleting Incidents', () => {
    it('should delete existing incident', async () => {
      const result = await controller.delete('INC-2026-001');
      expect(result.success).toBe(true);
      expect(result.id).toBe('INC-2026-001');
    });
  });
});
