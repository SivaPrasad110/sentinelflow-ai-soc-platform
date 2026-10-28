import { Test, TestingModule } from '@nestjs/testing';
import { IncidentsController } from './incidents.controller';
import { IncidentsService } from './incidents.service';
import { PrismaService } from '../prisma/prisma.service';
import { N8nIntegrationService } from '../n8n/n8n.service';
import { NotFoundException } from '@nestjs/common';
import { Severity, IncidentStatus, Role } from '@prisma/client';
import { AuthenticatedUser } from '../auth/decorators/current-user.decorator';

describe('IncidentsController & IncidentsService (Scoped Multi-Tenancy)', () => {
  let controller: IncidentsController;
  let service: IncidentsService;
  let prismaMock: any;
  let n8nMock: any;

  const currentOrgId = 'org-cyberdefense-001';
  const foreignOrgId = 'org-secops-002';

  const mockAnalyst: AuthenticatedUser = {
    id: 'USR-SOC-001',
    email: 'sarah.chen@sentinelflow.local',
    name: 'Sarah Chen',
    organizationId: currentOrgId,
    role: Role.ANALYST,
  };

  const sampleIncident = {
    id: 'INC-2026-001',
    title: 'Suspicious PowerShell Execution',
    description: 'Obfuscated command line detected on endpoint.',
    severity: Severity.CRITICAL,
    status: IncidentStatus.INVESTIGATING,
    organizationId: currentOrgId,
    tenantId: currentOrgId,
    assignedToId: mockAnalyst.id,
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
      id: mockAnalyst.id,
      name: mockAnalyst.name,
      email: mockAnalyst.email,
    },
  };

  const foreignIncident = {
    ...sampleIncident,
    id: 'INC-2026-FOREIGN',
    organizationId: foreignOrgId,
    tenantId: foreignOrgId,
    title: 'Foreign Org Incident',
  };

  beforeEach(async () => {
    prismaMock = {
      incident: {
        findMany: jest.fn().mockImplementation(({ where }) => {
          const targetOrg = where.OR?.[0]?.organizationId;
          if (targetOrg === currentOrgId) {
            return Promise.resolve([sampleIncident]);
          }
          if (targetOrg === foreignOrgId) {
            return Promise.resolve([foreignIncident]);
          }
          return Promise.resolve([]);
        }),
        findFirst: jest.fn().mockImplementation(({ where }) => {
          const targetOrg = where.OR?.[0]?.organizationId;
          if (where.id === sampleIncident.id && targetOrg === currentOrgId) {
            return Promise.resolve(sampleIncident);
          }
          if (where.id === foreignIncident.id && targetOrg === foreignOrgId) {
            return Promise.resolve(foreignIncident);
          }
          return Promise.resolve(null);
        }),
        create: jest.fn().mockImplementation(({ data }) => {
          return Promise.resolve({
            ...sampleIncident,
            ...data,
            id: 'INC-2026-NEW',
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

    n8nMock = {
      triggerTriage: jest.fn().mockImplementation((incidentId, orgId) => {
        if (incidentId === 'INC-2026-FOREIGN') {
          throw new NotFoundException('Incident not found in your organization.');
        }
        return Promise.resolve({
          id: 'ANALYSIS-001',
          incidentId,
          organizationId: orgId,
          status: 'COMPLETED',
          eventId: 'evt-1234',
          summary: 'PowerShell lateral movement detected',
          severityAssessment: 'CRITICAL',
          confidence: 0.95,
          evidence: ['PowerShell encoded command'],
          recommendedActions: ['Isolate host'],
          missingInformation: [],
          requiresHumanReview: true,
          createdAt: new Date().toISOString(),
        });
      }),
      getIncidentAnalyses: jest.fn().mockImplementation((incidentId, orgId) => {
        if (incidentId === 'INC-2026-FOREIGN') {
          throw new NotFoundException('Incident not found in your organization.');
        }
        return Promise.resolve([
          {
            id: 'ANALYSIS-001',
            incidentId,
            organizationId: orgId,
            status: 'COMPLETED',
            eventId: 'evt-1234',
            summary: 'PowerShell lateral movement detected',
            severityAssessment: 'CRITICAL',
            confidence: 0.95,
            evidence: ['PowerShell encoded command'],
            recommendedActions: ['Isolate host'],
            missingInformation: [],
            requiresHumanReview: true,
            createdAt: new Date().toISOString(),
          },
        ]);
      }),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [IncidentsController],
      providers: [
        IncidentsService,
        {
          provide: PrismaService,
          useValue: prismaMock,
        },
        {
          provide: N8nIntegrationService,
          useValue: n8nMock,
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

  describe('Scoped Organization Listing', () => {
    it('should only return incidents belonging to the authenticated organization', async () => {
      const incidents = await controller.findAll(currentOrgId);
      expect(Array.isArray(incidents)).toBe(true);
      expect(incidents.length).toBe(1);
      expect(incidents[0].id).toBe('INC-2026-001');
      expect(incidents[0].organizationId).toBe(currentOrgId);
    });
  });

  describe('Preventing Insecure Direct Object References (Cross-Tenant Access)', () => {
    it('should retrieve incident within authenticated organization', async () => {
      const result = await controller.findById('INC-2026-001', currentOrgId);
      expect(result).toBeDefined();
      expect(result.id).toBe('INC-2026-001');
    });

    it('should block cross-tenant IDOR access when querying foreign incident ID', async () => {
      // Attacker from currentOrg attempts to fetch incident belonging to foreignOrg
      await expect(
        controller.findById('INC-2026-FOREIGN', currentOrgId),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('Permitted Analyst Actions', () => {
    it('should allow analyst to create a new incident in authorized organization', async () => {
      const dto = {
        title: 'New Malware Outbreak',
        description: 'Lateral movement flagged on workstation.',
        severity: Severity.HIGH,
        status: IncidentStatus.NEW,
      };

      const created = await controller.create(dto, currentOrgId, mockAnalyst);
      expect(created).toBeDefined();
      expect(prismaMock.incident.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            organizationId: currentOrgId,
            assignedToId: mockAnalyst.id,
          }),
        }),
      );
    });

    it('should allow analyst to update an incident within their organization', async () => {
      const updateDto = { status: IncidentStatus.CONTAINED };
      const updated = await controller.update('INC-2026-001', updateDto, currentOrgId);
      expect(updated).toBeDefined();
      expect(prismaMock.incident.update).toHaveBeenCalled();
    });
  });

  describe('Deletion', () => {
    it('should delete incident within authorized organization', async () => {
      const result = await controller.delete('INC-2026-001', currentOrgId);
      expect(result.success).toBe(true);
      expect(prismaMock.incident.delete).toHaveBeenCalledWith({
        where: { id: 'INC-2026-001' },
      });
    });

    it('should prevent deleting foreign organization incident', async () => {
      await expect(
        controller.delete('INC-2026-FOREIGN', currentOrgId),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('n8n AI Incident Triage Integration', () => {
    it('should trigger AI triage for an incident in the authorized organization', async () => {
      const analysis = await controller.analyze('INC-2026-001', currentOrgId, mockAnalyst);
      expect(analysis).toBeDefined();
      expect(analysis.status).toBe('COMPLETED');
      expect(analysis.severityAssessment).toBe('CRITICAL');
      expect(n8nMock.triggerTriage).toHaveBeenCalledWith(
        'INC-2026-001',
        currentOrgId,
        mockAnalyst.id,
      );
    });

    it('should reject triage request for cross-tenant foreign organization incident', async () => {
      await expect(
        controller.analyze('INC-2026-FOREIGN', currentOrgId, mockAnalyst),
      ).rejects.toThrow(NotFoundException);
    });

    it('should retrieve analysis history for an incident within the organization', async () => {
      const history = await controller.getAnalyses('INC-2026-001', currentOrgId);
      expect(history).toHaveLength(1);
      expect(history[0].id).toBe('ANALYSIS-001');
      expect(n8nMock.getIncidentAnalyses).toHaveBeenCalledWith('INC-2026-001', currentOrgId);
    });

    it('should reject retrieving analysis history for cross-tenant incident', async () => {
      await expect(
        controller.getAnalyses('INC-2026-FOREIGN', currentOrgId),
      ).rejects.toThrow(NotFoundException);
    });
  });
});
