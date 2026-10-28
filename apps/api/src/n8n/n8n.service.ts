import {
  Injectable,
  Logger,
  NotFoundException,
  ConflictException,
  ServiceUnavailableException,
  BadGatewayException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { randomUUID } from 'crypto';
import { plainToInstance } from 'class-transformer';
import { validateSync } from 'class-validator';
import { N8nTriageResponseDto } from './dto/n8n-triage-response.dto';
import {
  IncidentAnalysisRecord,
  N8nTriageRequestPayload,
  AnalysisStatus,
  IOCType,
  AlertSeverity,
} from '@sentinelflow/shared';
import { TriageSeverity, AnalysisStatus as PrismaAnalysisStatus } from '@prisma/client';

@Injectable()
export class N8nIntegrationService {
  private readonly logger = new Logger(N8nIntegrationService.name);
  private readonly inFlightAnalyses = new Set<string>();

  constructor(
    private readonly configService: ConfigService,
    private readonly prisma: PrismaService,
  ) {}

  /**
   * Safe mapping from string severity to Prisma TriageSeverity enum
   */
  private mapTriageSeverity(severityStr: string): TriageSeverity {
    const normalized = severityStr.toUpperCase().trim();
    switch (normalized) {
      case 'INFORMATIONAL':
        return TriageSeverity.INFORMATIONAL;
      case 'LOW':
        return TriageSeverity.LOW;
      case 'MEDIUM':
        return TriageSeverity.MEDIUM;
      case 'HIGH':
        return TriageSeverity.HIGH;
      case 'CRITICAL':
        return TriageSeverity.CRITICAL;
      default:
        return TriageSeverity.MEDIUM;
    }
  }

  /**
   * Map Prisma IncidentAnalysis model to shared IncidentAnalysisRecord
   */
  private mapToSharedAnalysis(analysis: any): IncidentAnalysisRecord {
    return {
      id: analysis.id,
      incidentId: analysis.incidentId,
      organizationId: analysis.organizationId,
      status: analysis.status as AnalysisStatus,
      eventId: analysis.eventId,
      workflowId: analysis.workflowId || undefined,
      executionId: analysis.executionId || undefined,
      model: analysis.model || undefined,
      summary: analysis.summary || undefined,
      severityAssessment: analysis.severityAssessment || undefined,
      confidence: analysis.confidence !== null ? analysis.confidence : undefined,
      evidence: analysis.evidence || [],
      potentialImpact: analysis.potentialImpact || undefined,
      recommendedActions: analysis.recommendedActions || [],
      missingInformation: analysis.missingInformation || [],
      requiresHumanReview: analysis.requiresHumanReview,
      errorMessage: analysis.errorMessage || undefined,
      durationMs: analysis.durationMs || undefined,
      triggeredById: analysis.triggeredById || undefined,
      createdAt: analysis.createdAt.toISOString(),
      completedAt: analysis.completedAt ? analysis.completedAt.toISOString() : undefined,
    };
  }

  /**
   * Trigger an AI incident triage request to n8n Cloud
   */
  async triggerTriage(
    incidentId: string,
    organizationId: string,
    userId?: string,
  ): Promise<IncidentAnalysisRecord> {
    // 1. Verify incident ownership within the authorized organization (prevent cross-tenant IDOR)
    const incident = await this.prisma.incident.findFirst({
      where: {
        id: incidentId,
        OR: [
          { organizationId },
          { tenantId: organizationId },
        ],
      },
      include: {
        iocs: true,
        alerts: true,
      },
    });

    if (!incident) {
      throw new NotFoundException(`Incident "${incidentId}" not found in your organization.`);
    }

    // 2. Prevent duplicate concurrent in-flight triage executions for the same incident
    if (this.inFlightAnalyses.has(incidentId)) {
      throw new ConflictException(`AI Triage is already in progress for incident "${incidentId}".`);
    }

    // 3. Verify server-side configuration
    const webhookUrl = this.configService.get<string>('N8N_WEBHOOK_URL');
    const webhookSecret = this.configService.get<string>('N8N_WEBHOOK_SECRET');

    if (!webhookUrl || !webhookSecret) {
      this.logger.error('N8N_WEBHOOK_URL or N8N_WEBHOOK_SECRET is not configured on server');
      throw new ServiceUnavailableException('n8n automation service is unconfigured on the server.');
    }

    this.inFlightAnalyses.add(incidentId);
    const eventId = `evt-${randomUUID()}`;
    const startTime = Date.now();

    // 4. Create initial PENDING analysis record in PostgreSQL
    const initialRecord = await this.prisma.incidentAnalysis.create({
      data: {
        incidentId: incident.id,
        organizationId: incident.organizationId || organizationId,
        status: PrismaAnalysisStatus.PENDING,
        eventId,
        triggeredById: userId || undefined,
      },
    });

    // 5. Sanitize and prepare minimal telemetry payload (strip sensitive secrets/tokens, cap lengths)
    const sanitizedPayload: N8nTriageRequestPayload = {
      eventId,
      incidentId: incident.id,
      title: incident.title.slice(0, 200),
      description: incident.description.slice(0, 1500),
      severity: incident.severity as AlertSeverity,
      status: incident.status,
      organizationId: incident.organizationId || organizationId,
      iocs: incident.iocs.slice(0, 15).map((ioc) => ({
        type: ioc.type as IOCType,
        value: ioc.value.slice(0, 255),
        threatScore: ioc.threatScore !== null ? ioc.threatScore : undefined,
      })),
      detectedAlertsCount: incident.alerts.length,
      detectedAlertsSummary: incident.alerts.slice(0, 5).map((alert) => ({
        title: alert.title.slice(0, 150),
        source: alert.source,
        severity: alert.severity as AlertSeverity,
      })),
      timestamp: new Date().toISOString(),
    };

    try {
      // 6. Dispatch HTTP request with 20s timeout and bounded retries on transient errors
      const responseData = await this.dispatchToN8n(webhookUrl, webhookSecret, sanitizedPayload);

      // 7. Validate response using class-validator DTO
      const dto = plainToInstance(N8nTriageResponseDto, responseData);
      const validationErrors = validateSync(dto);

      if (validationErrors.length > 0) {
        const errorDetails = validationErrors.map((e) => Object.values(e.constraints || {}).join(', ')).join('; ');
        this.logger.warn(`Malformed AI response received from n8n for incident ${incidentId}: ${errorDetails}`);

        await this.prisma.incidentAnalysis.update({
          where: { id: initialRecord.id },
          data: {
            status: PrismaAnalysisStatus.FAILED,
            errorMessage: `Validation failed for n8n AI response: ${errorDetails}`.slice(0, 500),
            rawResponse: responseData as any,
            durationMs: Date.now() - startTime,
            completedAt: new Date(),
          },
        });

        throw new BadGatewayException(`Received malformed analysis schema from n8n AI workflow: ${errorDetails}`);
      }

      // 8. Persist COMPLETED analysis in database
      const triageSeverity = this.mapTriageSeverity(dto.severity_assessment);
      const durationMs = Date.now() - startTime;

      const completedRecord = await this.prisma.incidentAnalysis.update({
        where: { id: initialRecord.id },
        data: {
          status: PrismaAnalysisStatus.COMPLETED,
          summary: dto.summary,
          severityAssessment: triageSeverity,
          confidence: dto.confidence,
          evidence: dto.evidence,
          potentialImpact: dto.potential_impact,
          recommendedActions: dto.recommended_actions,
          missingInformation: dto.missing_information,
          requiresHumanReview: dto.requires_human_review,
          durationMs,
          rawResponse: responseData as any,
          completedAt: new Date(),
        },
      });

      // 9. Update Incident advisory AI triage fields
      await this.prisma.incident.update({
        where: { id: incident.id },
        data: {
          aiSummary: dto.summary,
          aiRiskScore: dto.confidence,
          mitigationSteps: dto.recommended_actions,
          aiAnalysis: {
            summary: dto.summary,
            riskAssessment: dto.potential_impact,
            recommendedMitigations: dto.recommended_actions,
            confidenceScore: dto.confidence,
            analyzedAt: new Date().toISOString(),
            modelUsed: 'n8n-ai-agent (advisory)',
            requiresHumanReview: dto.requires_human_review,
            missingInformation: dto.missing_information,
            advisorySeverity: dto.severity_assessment,
          },
          // If incident was in NEW state, transition to TRIAGED
          ...(incident.status === 'NEW' ? { status: 'TRIAGED' } : {}),
        },
      });

      return this.mapToSharedAnalysis(completedRecord);
    } catch (err: any) {
      const errorMessage = err?.message || 'Unknown error occurred while contacting n8n';
      this.logger.error(`n8n triage failed for incident ${incidentId}: ${errorMessage}`);

      // Ensure FAILED state is recorded if not already handled
      await this.prisma.incidentAnalysis.updateMany({
        where: {
          id: initialRecord.id,
          status: PrismaAnalysisStatus.PENDING,
        },
        data: {
          status: PrismaAnalysisStatus.FAILED,
          errorMessage: errorMessage.slice(0, 500),
          durationMs: Date.now() - startTime,
          completedAt: new Date(),
        },
      });

      if (
        err instanceof NotFoundException ||
        err instanceof ConflictException ||
        err instanceof ServiceUnavailableException ||
        err instanceof BadGatewayException
      ) {
        throw err;
      }

      throw new BadGatewayException(`Failed to communicate with n8n AI triage workflow: ${errorMessage}`);
    } finally {
      this.inFlightAnalyses.delete(incidentId);
    }
  }

  /**
   * Dispatch HTTP POST with timeout and 1 bounded retry on transient network errors
   */
  private async dispatchToN8n(
    webhookUrl: string,
    webhookSecret: string,
    payload: N8nTriageRequestPayload,
  ): Promise<any> {
    const maxAttempts = 2; // initial + 1 bounded retry for transient network failure
    let lastError: Error | null = null;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 20000); // 20-second timeout

      try {
        const response = await fetch(webhookUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-SentinelFlow-Secret': webhookSecret,
            'X-Event-ID': payload.eventId,
            'X-Incident-ID': payload.incidentId,
          },
          body: JSON.stringify(payload),
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
          const status = response.status;
          let errorText = '';
          try {
            errorText = await response.text();
          } catch {
            errorText = response.statusText;
          }

          // If 502/503/504 transient error, retry once
          if ((status === 502 || status === 503 || status === 504) && attempt < maxAttempts) {
            this.logger.warn(`n8n returned HTTP ${status}. Retrying attempt ${attempt + 1}/${maxAttempts}...`);
            await new Promise((resolve) => setTimeout(resolve, 1000));
            continue;
          }

          throw new BadGatewayException(
            `n8n webhook returned HTTP ${status}: ${errorText.slice(0, 200)}`,
          );
        }

        const data = await response.json();
        return data;
      } catch (err: any) {
        clearTimeout(timeoutId);
        if (err.name === 'AbortError') {
          // Do not retry on client-side timeout to avoid creating duplicate runs
          throw new BadGatewayException('n8n AI incident triage request timed out after 20 seconds.');
        }

        lastError = err;
        if (attempt < maxAttempts) {
          this.logger.warn(`Network error contacting n8n (${err.message}). Retrying attempt ${attempt + 1}...`);
          await new Promise((resolve) => setTimeout(resolve, 1000));
        }
      }
    }

    throw lastError || new Error('Failed to dispatch request to n8n');
  }

  /**
   * Retrieve analysis history for an incident within the authorized organization
   */
  async getIncidentAnalyses(
    incidentId: string,
    organizationId: string,
  ): Promise<IncidentAnalysisRecord[]> {
    // Verify incident belongs to organization
    const incident = await this.prisma.incident.findFirst({
      where: {
        id: incidentId,
        OR: [
          { organizationId },
          { tenantId: organizationId },
        ],
      },
    });

    if (!incident) {
      throw new NotFoundException(`Incident "${incidentId}" not found in your organization.`);
    }

    const analyses = await this.prisma.incidentAnalysis.findMany({
      where: {
        incidentId,
        OR: [
          { organizationId },
          { incident: { tenantId: organizationId } },
        ],
      },
      orderBy: { createdAt: 'desc' },
    });

    return analyses.map((a) => this.mapToSharedAnalysis(a));
  }

  /**
   * Real connectivity check probe distinguishing unconfigured, reachable, and unreachable
   */
  async checkConnectivity(): Promise<'reachable' | 'configured' | 'unreachable' | 'unconfigured'> {
    const webhookUrl = this.configService.get<string>('N8N_WEBHOOK_URL');
    if (!webhookUrl) {
      return 'unconfigured';
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000); // 3-second quick probe

    try {
      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-SentinelFlow-Probe': 'health-check',
        },
        body: JSON.stringify({ ping: true }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      // Any HTTP response (even 400, 401, or 404 from webhook node) proves the n8n endpoint is reachable
      if (response.status > 0) {
        return 'reachable';
      }
      return 'configured';
    } catch (err: any) {
      clearTimeout(timeoutId);
      this.logger.debug(`n8n connectivity check failed: ${err.message}`);
      return 'unreachable';
    }
  }
}
