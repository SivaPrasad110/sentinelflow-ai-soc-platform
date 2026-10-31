import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { DetectionService } from './detection.service';
import { MitreAttackService } from './mitre/mitre-attack.service';
import { RiskScoringService } from './risk-scoring/risk-scoring.service';
import { PrismaService } from '../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import { EventsGateway } from '../events/events.gateway';
import { IncidentsService } from '../incidents/incidents.service';
import { Severity } from '@prisma/client';

describe('DetectionService (Detection Engine & Finding Correlation)', () => {
  let service: DetectionService;
  let prismaMock: any;
  let mitreService: MitreAttackService;
  let riskScoringService: RiskScoringService;
  let auditMock: any;
  let eventsMock: any;
  let incidentsMock: any;

  const orgId = 'org-sentinel-corp';

  beforeEach(async () => {
    prismaMock = {
      detectionRule: {
        count: jest.fn().mockResolvedValue(1),
        findMany: jest.fn(),
        findFirst: jest.fn(),
        create: jest.fn(),
        update: jest.fn(),
        delete: jest.fn(),
      },
      indicatorOfCompromise: {
        findMany: jest.fn().mockResolvedValue([]),
      },
      securityFinding: {
        findFirst: jest.fn(),
        findMany: jest.fn(),
        create: jest.fn(),
        update: jest.fn(),
      },
      incident: {
        create: jest.fn(),
      },
    };

    auditMock = {
      log: jest.fn().mockResolvedValue({}),
    };

    eventsMock = {
      broadcastToOrg: jest.fn(),
    };

    incidentsMock = {
      create: jest.fn().mockResolvedValue({
        id: 'INC-ESCALATED-101',
        title: '[Escalated] Suspicious Activity',
        description: 'Auto escalated',
        severity: 'HIGH',
        status: 'NEW',
        organizationId: orgId,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      }),
      findById: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DetectionService,
        MitreAttackService,
        RiskScoringService,
        { provide: PrismaService, useValue: prismaMock },
        { provide: AuditService, useValue: auditMock },
        { provide: EventsGateway, useValue: eventsMock },
        { provide: IncidentsService, useValue: incidentsMock },
      ],
    }).compile();

    service = module.get<DetectionService>(DetectionService);
    mitreService = module.get<MitreAttackService>(MitreAttackService);
    riskScoringService = module.get<RiskScoringService>(RiskScoringService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('createRule', () => {
    it('should validate and create rule with valid MITRE ATT&CK technique', async () => {
      const mockCreated = {
        id: 'rule-powershell',
        name: 'Custom PowerShell Detection',
        description: 'Detects base64 encoded powershell execution',
        severity: Severity.HIGH,
        ruleType: 'PATTERN',
        criteria: [{ field: 'title', operator: 'CONTAINS', value: 'PowerShell' }],
        mitreTactic: 'Execution',
        mitreTechnique: 'Command and Scripting Interpreter: PowerShell',
        mitreTechniqueId: 'T1059.001',
        enabled: true,
        triggerCount: 0,
        organizationId: orgId,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      prismaMock.detectionRule.create.mockResolvedValue(mockCreated);

      const result = await service.createRule(
        {
          name: 'Custom PowerShell Detection',
          description: 'Detects base64 encoded powershell execution',
          severity: Severity.HIGH,
          ruleType: 'PATTERN',
          criteria: [{ field: 'title', operator: 'CONTAINS', value: 'PowerShell' }],
          mitreTechniqueId: 'T1059.001',
        },
        orgId,
      );

      expect(result).toBeDefined();
      expect(result.id).toBe('rule-powershell');
      expect(result.mitreTechniqueId).toBe('T1059.001');
      expect(auditMock.log).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'DETECTION_RULE_CREATE' }),
      );
    });

    it('should reject invalid / unsupported MITRE technique ID', async () => {
      await expect(
        service.createRule(
          {
            name: 'Fake Technique Rule',
            description: 'Fake',
            criteria: [],
            mitreTechniqueId: 'T9999.999', // Unsupported/non-existent
          },
          orgId,
        ),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('evaluateAlert', () => {
    it('should evaluate incoming alert and generate finding when rule matches', async () => {
      const mockRule = {
        id: 'rule-ps',
        name: 'Suspicious PowerShell Execution',
        description: 'Detects PowerShell invocations',
        severity: Severity.HIGH,
        ruleType: 'PATTERN',
        criteria: [{ field: 'title', operator: 'CONTAINS', value: 'powershell' }],
        mitreTactic: 'Execution',
        mitreTechnique: 'Command and Scripting Interpreter: PowerShell',
        mitreTechniqueId: 'T1059.001',
        enabled: true,
        organizationId: orgId,
      };

      prismaMock.detectionRule.findMany.mockResolvedValue([mockRule]);
      prismaMock.indicatorOfCompromise.findMany.mockResolvedValue([]);
      prismaMock.securityFinding.findFirst.mockResolvedValue(null); // No duplicate
      prismaMock.detectionRule.update.mockResolvedValue({});

      const mockFinding = {
        id: 'find-101',
        organizationId: orgId,
        ruleId: 'rule-ps',
        title: '[Detection] Suspicious PowerShell Execution: Encoded powershell executed',
        description: 'Mock alert description',
        severity: Severity.HIGH,
        riskScore: 65,
        riskBreakdown: { totalScore: 65 },
        evidence: {},
        mitreTactic: 'Execution',
        mitreTechnique: 'Command and Scripting Interpreter: PowerShell',
        mitreTechniqueId: 'T1059.001',
        fingerprint: 'abc123hash',
        status: 'NEW',
        createdAt: new Date(),
        updatedAt: new Date(),
        rule: mockRule,
      };
      prismaMock.securityFinding.create.mockResolvedValue(mockFinding);

      const rawAlert: any = {
        id: 'alert-1',
        title: 'Encoded PowerShell command executed on endpoint WKSTN-02',
        description: 'powershell.exe -enc aW52b2tlLW1pbWlrYXR6',
        severity: Severity.HIGH,
        source: 'EDR-Sentinel',
        detectedAt: new Date(),
        createdAt: new Date(),
      };

      const findings = await service.evaluateAlert(rawAlert, orgId);

      expect(findings).toHaveLength(1);
      expect(findings[0].id).toBe('find-101');
      expect(eventsMock.broadcastToOrg).toHaveBeenCalledWith(
        orgId,
        'finding:created',
        expect.any(Object),
      );
      expect(auditMock.log).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'FINDING_GENERATED' }),
      );
    });

    it('should suppress duplicate findings and update existing finding when duplicate alert arrives', async () => {
      const mockRule = {
        id: 'rule-ps',
        name: 'Suspicious PowerShell Execution',
        description: 'Detects PowerShell invocations',
        severity: Severity.HIGH,
        ruleType: 'PATTERN',
        criteria: [{ field: 'title', operator: 'CONTAINS', value: 'powershell' }],
        mitreTactic: 'Execution',
        mitreTechniqueId: 'T1059.001',
        enabled: true,
        organizationId: orgId,
      };

      prismaMock.detectionRule.findMany.mockResolvedValue([mockRule]);
      prismaMock.indicatorOfCompromise.findMany.mockResolvedValue([]);

      const existingFinding = {
        id: 'existing-find-1',
        fingerprint: 'already-seen-fingerprint',
        evidence: { duplicateCount: 1 },
        alertId: 'alert-initial',
        organizationId: orgId,
      };
      prismaMock.securityFinding.findFirst.mockResolvedValue(existingFinding);
      prismaMock.securityFinding.update.mockResolvedValue({
        ...existingFinding,
        title: '[Detection] PowerShell',
        description: 'dup',
        severity: Severity.HIGH,
        riskScore: 65,
        status: 'NEW',
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const duplicateAlert: any = {
        id: 'alert-dup-2',
        title: 'PowerShell script execution',
        description: 'Repeat alert',
        severity: Severity.HIGH,
        source: 'EDR-Sentinel',
      };

      const findings = await service.evaluateAlert(duplicateAlert, orgId);

      expect(findings).toHaveLength(1);
      expect(prismaMock.securityFinding.create).not.toHaveBeenCalled();
      expect(prismaMock.securityFinding.update).toHaveBeenCalled();
    });
  });

  describe('promoteToIncident', () => {
    it('should promote security finding into a formal incident', async () => {
      const mockFinding = {
        id: 'find-promote-1',
        organizationId: orgId,
        ruleId: 'rule-c2',
        title: '[Detection] Cobalt Strike C2 Beacon Detection: Malicious Beacon Traffic',
        description: 'Beacon telemetry detected',
        severity: Severity.CRITICAL,
        riskScore: 92,
        evidence: {},
        mitreTactic: 'Command and Control',
        mitreTechnique: 'Web Protocols',
        mitreTechniqueId: 'T1071.001',
        fingerprint: 'fprint-1',
        status: 'NEW',
        createdAt: new Date(),
        updatedAt: new Date(),
        rule: { name: 'Cobalt Strike C2 Beacon Detection' },
      };

      prismaMock.securityFinding.findFirst.mockResolvedValue(mockFinding);
      prismaMock.securityFinding.update.mockResolvedValue({
        ...mockFinding,
        status: 'PROMOTED',
        incidentId: 'INC-ESCALATED-101',
      });

      const incident = await service.promoteToIncident('find-promote-1', orgId);

      expect(incident).toBeDefined();
      expect(incident.id).toBe('INC-ESCALATED-101');
      expect(incidentsMock.create).toHaveBeenCalled();
      expect(prismaMock.securityFinding.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'find-promote-1' },
          data: expect.objectContaining({ status: 'PROMOTED' }),
        }),
      );
      expect(auditMock.log).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'FINDING_PROMOTED' }),
      );
    });
  });
});
