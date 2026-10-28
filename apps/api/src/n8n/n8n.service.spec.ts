import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { N8nIntegrationService } from './n8n.service';
import { PrismaService } from '../prisma/prisma.service';
import {
  NotFoundException,
  ConflictException,
  ServiceUnavailableException,
  BadGatewayException,
} from '@nestjs/common';
import { Severity, IncidentStatus, AnalysisStatus } from '@prisma/client';

describe('N8nIntegrationService', () => {
  let service: N8nIntegrationService;
  let configService: ConfigService;
  let prisma: PrismaService;

  const mockOrgId = 'org-cyberdefense-001';
  const mockUserId = 'usr-analyst-001';
  const mockWebhookUrl = 'https://siva11016.app.n8n.cloud/webhook/sentinelflow/incident-triage';
  const mockWebhookSecret = '322a987dce403bc4b73da31c1b20c7cc36926285f788ef18498bb36d5b42442e';

  const mockIncident = {
    id: 'INC-2026-001',
    title: 'Suspicious PowerShell Execution',
    description: 'Obfuscated command line detected on endpoint.',
    severity: Severity.CRITICAL,
    status: IncidentStatus.NEW,
    organizationId: mockOrgId,
    tenantId: mockOrgId,
    iocs: [
      { id: 'ioc-1', type: 'IP', value: '198.51.100.42', threatScore: 90 },
      { id: 'ioc-2', type: 'DOMAIN', value: 'malicious-c2.test', threatScore: 95 },
    ],
    alerts: [
      { id: 'alt-1', title: 'Suspicious Process', source: 'CrowdStrike EDR', severity: Severity.HIGH },
    ],
  };

  const validN8nResponse = {
    summary: 'PowerShell execution consistent with initial access and discovery.',
    severity_assessment: 'critical',
    confidence: 0.94,
    evidence: ['PowerShell encoded arguments', 'Beaconing to malicious-c2.test'],
    potential_impact: 'High risk of credential theft and domain compromise.',
    recommended_actions: [
      'Isolate endpoint from local network',
      'Revoke user credentials and invalidate refresh tokens',
    ],
    missing_information: ['Command-line parent process GUID'],
    requires_human_review: true,
  };

  let prismaMock: any;
  let configValues: Record<string, string | undefined>;
  let originalFetch: typeof global.fetch;

  beforeEach(async () => {
    configValues = {
      N8N_WEBHOOK_URL: mockWebhookUrl,
      N8N_WEBHOOK_SECRET: mockWebhookSecret,
    };

    prismaMock = {
      incident: {
        findFirst: jest.fn().mockImplementation(({ where }) => {
          if (where.id === mockIncident.id && (where.OR?.[0]?.organizationId === mockOrgId || where.tenantId === mockOrgId)) {
            return Promise.resolve(mockIncident);
          }
          return Promise.resolve(null);
        }),
        update: jest.fn().mockResolvedValue({ ...mockIncident, status: IncidentStatus.TRIAGED }),
      },
      incidentAnalysis: {
        create: jest.fn().mockImplementation(({ data }) => {
          return Promise.resolve({
            id: 'analysis-rec-001',
            ...data,
            createdAt: new Date(),
          });
        }),
        update: jest.fn().mockImplementation(({ where, data }) => {
          return Promise.resolve({
            id: where.id,
            incidentId: mockIncident.id,
            organizationId: mockOrgId,
            eventId: 'evt-test-123',
            createdAt: new Date(),
            ...data,
          });
        }),
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
        findMany: jest.fn().mockResolvedValue([
          {
            id: 'analysis-rec-001',
            incidentId: mockIncident.id,
            organizationId: mockOrgId,
            status: AnalysisStatus.COMPLETED,
            eventId: 'evt-test-123',
            summary: validN8nResponse.summary,
            severityAssessment: 'CRITICAL',
            confidence: 0.94,
            evidence: validN8nResponse.evidence,
            recommendedActions: validN8nResponse.recommended_actions,
            missingInformation: validN8nResponse.missing_information,
            requiresHumanReview: true,
            createdAt: new Date(),
          },
        ]),
      },
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        N8nIntegrationService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => configValues[key]),
          },
        },
        {
          provide: PrismaService,
          useValue: prismaMock,
        },
      ],
    }).compile();

    service = module.get<N8nIntegrationService>(N8nIntegrationService);
    configService = module.get<ConfigService>(ConfigService);
    prisma = module.get<PrismaService>(PrismaService);

    originalFetch = global.fetch;
  });

  afterEach(() => {
    global.fetch = originalFetch;
    jest.clearAllMocks();
  });

  describe('Configuration & Header Authentication', () => {
    it('should fail safely if N8N_WEBHOOK_URL is not configured', async () => {
      configValues['N8N_WEBHOOK_URL'] = undefined;

      await expect(
        service.triggerTriage(mockIncident.id, mockOrgId, mockUserId),
      ).rejects.toThrow(ServiceUnavailableException);
    });

    it('should fail safely if N8N_WEBHOOK_SECRET is not configured', async () => {
      configValues['N8N_WEBHOOK_SECRET'] = undefined;

      await expect(
        service.triggerTriage(mockIncident.id, mockOrgId, mockUserId),
      ).rejects.toThrow(ServiceUnavailableException);
    });

    it('should dispatch request using exact X-SentinelFlow-Secret and correlation headers', async () => {
      let capturedUrl = '';
      let capturedHeaders: any = {};
      let capturedBody: any = {};

      global.fetch = jest.fn().mockImplementation((url, init) => {
        capturedUrl = url.toString();
        capturedHeaders = init.headers;
        capturedBody = JSON.parse(init.body);
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve(validN8nResponse),
        });
      });

      const result = await service.triggerTriage(mockIncident.id, mockOrgId, mockUserId);

      expect(result).toBeDefined();
      expect(capturedUrl).toBe(mockWebhookUrl);
      expect(capturedHeaders['X-SentinelFlow-Secret']).toBe(mockWebhookSecret);
      expect(capturedHeaders['Content-Type']).toBe('application/json');
      expect(capturedHeaders['X-Event-ID']).toMatch(/^evt-/);
      expect(capturedHeaders['X-Incident-ID']).toBe(mockIncident.id);
      expect(capturedBody.incidentId).toBe(mockIncident.id);
      expect(capturedBody.title).toBe(mockIncident.title);
      expect(capturedBody.iocs).toHaveLength(2);
    });
  });

  describe('Tenant Scoping & Multi-Tenancy', () => {
    it('should reject triage when incident does not belong to authorized organization', async () => {
      await expect(
        service.triggerTriage(mockIncident.id, 'org-foreign-999', mockUserId),
      ).rejects.toThrow(NotFoundException);
    });

    it('should reject history query when incident is outside authorized organization', async () => {
      await expect(
        service.getIncidentAnalyses(mockIncident.id, 'org-foreign-999'),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('Response Validation & Schema Rules', () => {
    it('should successfully parse, validate, and persist complete valid AI triage output', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: () => Promise.resolve(validN8nResponse),
      });

      const result = await service.triggerTriage(mockIncident.id, mockOrgId, mockUserId);

      expect(result.status).toBe('COMPLETED');
      expect(result.severityAssessment).toBe('CRITICAL');
      expect(result.confidence).toBe(0.94);
      expect(result.requiresHumanReview).toBe(true);
      expect(result.recommendedActions).toHaveLength(2);

      // Verify Incident was transitioned to TRIAGED
      expect(prismaMock.incident.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: mockIncident.id },
          data: expect.objectContaining({
            status: 'TRIAGED',
            aiRiskScore: 0.94,
          }),
        }),
      );
    });

    it('should reject malformed AI output missing required summary', async () => {
      const invalidResponse = { ...validN8nResponse, summary: '' };

      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: () => Promise.resolve(invalidResponse),
      });

      await expect(
        service.triggerTriage(mockIncident.id, mockOrgId, mockUserId),
      ).rejects.toThrow(BadGatewayException);

      // Verify analysis is updated to FAILED
      expect(prismaMock.incidentAnalysis.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            status: AnalysisStatus.FAILED,
          }),
        }),
      );
    });

    it('should reject malformed output with confidence out of range (> 1.0)', async () => {
      const invalidResponse = { ...validN8nResponse, confidence: 1.5 };

      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: () => Promise.resolve(invalidResponse),
      });

      await expect(
        service.triggerTriage(mockIncident.id, mockOrgId, mockUserId),
      ).rejects.toThrow(BadGatewayException);
    });

    it('should reject malformed output with invalid severity string', async () => {
      const invalidResponse = { ...validN8nResponse, severity_assessment: 'catastrophic_mega_danger' };

      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: () => Promise.resolve(invalidResponse),
      });

      await expect(
        service.triggerTriage(mockIncident.id, mockOrgId, mockUserId),
      ).rejects.toThrow(BadGatewayException);
    });
  });

  describe('Timeouts, Retries & Duplicate Prevention', () => {
    it('should handle request timeout safely and record FAILED status', async () => {
      global.fetch = jest.fn().mockImplementation(() => {
        const err: any = new Error('The operation was aborted');
        err.name = 'AbortError';
        return Promise.reject(err);
      });

      await expect(
        service.triggerTriage(mockIncident.id, mockOrgId, mockUserId),
      ).rejects.toThrow(BadGatewayException);

      expect(prismaMock.incidentAnalysis.updateMany).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            status: AnalysisStatus.FAILED,
          }),
        }),
      );
    });

    it('should perform bounded retry on transient HTTP 503 error and succeed', async () => {
      let callCount = 0;
      global.fetch = jest.fn().mockImplementation(() => {
        callCount++;
        if (callCount === 1) {
          return Promise.resolve({
            ok: false,
            status: 503,
            statusText: 'Service Temporarily Unavailable',
            text: () => Promise.resolve('n8n warming up'),
          });
        }
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve(validN8nResponse),
        });
      });

      const result = await service.triggerTriage(mockIncident.id, mockOrgId, mockUserId);
      expect(result).toBeDefined();
      expect(callCount).toBe(2);
    });

    it('should prevent concurrent duplicate triage executions for the same incident', async () => {
      let resolveFirst: any;
      const firstPromise = new Promise((resolve) => {
        resolveFirst = resolve;
      });

      global.fetch = jest.fn().mockImplementation(() => firstPromise);

      const triggerPromise1 = service.triggerTriage(mockIncident.id, mockOrgId, mockUserId);

      // Attempt second concurrent trigger for same incident
      await expect(
        service.triggerTriage(mockIncident.id, mockOrgId, mockUserId),
      ).rejects.toThrow(ConflictException);

      // Clean up first execution
      resolveFirst({
        ok: true,
        status: 200,
        json: () => Promise.resolve(validN8nResponse),
      });

      await triggerPromise1;
    });
  });

  describe('Connectivity Probe', () => {
    it('should return reachable when endpoint responds', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        status: 200,
      });

      const status = await service.checkConnectivity();
      expect(status).toBe('reachable');
    });

    it('should return unreachable when endpoint throws network error', async () => {
      global.fetch = jest.fn().mockRejectedValue(new Error('Connection refused'));

      const status = await service.checkConnectivity();
      expect(status).toBe('unreachable');
    });

    it('should return unconfigured if URL is missing', async () => {
      configValues['N8N_WEBHOOK_URL'] = undefined;

      const status = await service.checkConnectivity();
      expect(status).toBe('unconfigured');
    });
  });
});
