import {
  Injectable,
  NotFoundException,
  BadRequestException,
  Logger,
  Optional,
  Inject,
  forwardRef,
} from '@nestjs/common';
import * as crypto from 'crypto';
import { PrismaService } from '../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import { EventsGateway } from '../events/events.gateway';
import { MitreAttackService } from './mitre/mitre-attack.service';
import { RiskScoringService } from './risk-scoring/risk-scoring.service';
import { IncidentsService } from '../incidents/incidents.service';
import { CreateRuleDto } from './dto/create-rule.dto';
import { UpdateRuleDto } from './dto/update-rule.dto';
import {
  DetectionRule as SharedDetectionRule,
  DetectionRuleCriterion,
  DetectionRuleType,
  SecurityFinding as SharedSecurityFinding,
  FindingStatus,
  AlertSeverity,
  Incident as SharedIncident,
  IndicatorOfCompromise as SharedIOC,
  RiskScoreBreakdown,
} from '@sentinelflow/shared';
import {
  DetectionRule as PrismaDetectionRule,
  SecurityFinding as PrismaSecurityFinding,
  SecurityAlert as PrismaAlert,
  Severity,
} from '@prisma/client';
import { AuthenticatedUser } from '../auth/decorators/current-user.decorator';

function getNestedValue(obj: any, path: string): any {
  if (!obj || !path) return undefined;
  const parts = path.split('.');
  let curr = obj;
  for (const part of parts) {
    if (curr === null || curr === undefined) return undefined;
    curr = curr[part];
  }
  return curr;
}

function evaluateCriterion(targetValue: any, operator: string, ruleValue: any): boolean {
  if (targetValue === undefined || targetValue === null) return false;

  switch (operator) {
    case 'EQUALS':
      return String(targetValue).toLowerCase() === String(ruleValue).toLowerCase();
    case 'CONTAINS':
      return String(targetValue).toLowerCase().includes(String(ruleValue).toLowerCase());
    case 'STARTS_WITH':
      return String(targetValue).toLowerCase().startsWith(String(ruleValue).toLowerCase());
    case 'REGEX':
      try {
        const regex = new RegExp(String(ruleValue), 'i');
        return regex.test(String(targetValue));
      } catch {
        return false;
      }
    case 'IN':
      if (Array.isArray(ruleValue)) {
        return ruleValue.map((v) => String(v).toLowerCase()).includes(String(targetValue).toLowerCase());
      }
      return String(ruleValue).toLowerCase().includes(String(targetValue).toLowerCase());
    case 'GREATER_THAN':
      return Number(targetValue) > Number(ruleValue);
    default:
      return false;
  }
}

@Injectable()
export class DetectionService {
  private readonly logger = new Logger(DetectionService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly mitreService: MitreAttackService,
    private readonly riskScoringService: RiskScoringService,
    @Optional() private readonly auditService?: AuditService,
    @Optional() private readonly eventsGateway?: EventsGateway,
    @Optional() @Inject(forwardRef(() => IncidentsService)) private readonly incidentsService?: IncidentsService,
  ) {}

  private mapToSharedRule(rule: PrismaDetectionRule): SharedDetectionRule {
    return {
      id: rule.id,
      name: rule.name,
      description: rule.description,
      organizationId: rule.organizationId,
      severity: rule.severity as AlertSeverity,
      ruleType: rule.ruleType as DetectionRuleType,
      criteria: (rule.criteria as any) || [],
      mitreTactic: rule.mitreTactic || undefined,
      mitreTechnique: rule.mitreTechnique || undefined,
      mitreTechniqueId: rule.mitreTechniqueId || undefined,
      enabled: rule.enabled,
      lastTriggeredAt: rule.lastTriggeredAt ? rule.lastTriggeredAt.toISOString() : undefined,
      triggerCount: rule.triggerCount,
      createdAt: rule.createdAt.toISOString(),
      updatedAt: rule.updatedAt.toISOString(),
    };
  }

  private mapToSharedFinding(finding: PrismaSecurityFinding & { rule?: PrismaDetectionRule | null }): SharedSecurityFinding {
    return {
      id: finding.id,
      organizationId: finding.organizationId,
      ruleId: finding.ruleId || undefined,
      ruleName: finding.rule?.name || undefined,
      title: finding.title,
      description: finding.description,
      severity: finding.severity as AlertSeverity,
      riskScore: finding.riskScore,
      riskBreakdown: (finding.riskBreakdown as unknown as RiskScoreBreakdown) || undefined,
      evidence: (finding.evidence as Record<string, unknown>) || {},
      mitreTactic: finding.mitreTactic || undefined,
      mitreTechnique: finding.mitreTechnique || undefined,
      mitreTechniqueId: finding.mitreTechniqueId || undefined,
      alertId: finding.alertId || undefined,
      incidentId: finding.incidentId || undefined,
      fingerprint: finding.fingerprint,
      status: finding.status as FindingStatus,
      createdAt: finding.createdAt.toISOString(),
      updatedAt: finding.updatedAt.toISOString(),
    };
  }

  /**
   * Seed default detection rules for an organization if none exist
   */
  async seedDefaultRulesIfEmpty(organizationId: string): Promise<void> {
    const count = await this.prisma.detectionRule.count({
      where: { organizationId },
    });

    if (count > 0) return;

    this.logger.log(`Seeding default detection rules for organization: ${organizationId}`);

    const defaultRules: Array<{
      name: string;
      description: string;
      severity: Severity;
      ruleType: string;
      criteria: DetectionRuleCriterion[];
      mitreTactic: string;
      mitreTechnique: string;
      mitreTechniqueId: string;
    }> = [
      {
        name: 'Suspicious PowerShell Execution',
        description: 'Detects encoded, download-string, or bypass command executions via PowerShell interpreter.',
        severity: Severity.HIGH,
        ruleType: 'PATTERN',
        criteria: [
          { field: 'title', operator: 'CONTAINS', value: 'PowerShell' },
        ],
        mitreTactic: 'Execution',
        mitreTechnique: 'Command and Scripting Interpreter: PowerShell',
        mitreTechniqueId: 'T1059.001',
      },
      {
        name: 'Cobalt Strike C2 Beacon Detection',
        description: 'Correlates network telemetry matching known Cobalt Strike teamserver signatures or C2 beacon intervals.',
        severity: Severity.CRITICAL,
        ruleType: 'IOC_MATCH',
        criteria: [
          { field: 'title', operator: 'CONTAINS', value: 'Cobalt Strike' },
        ],
        mitreTactic: 'Command and Control',
        mitreTechnique: 'Application Layer Protocol: Web Protocols',
        mitreTechniqueId: 'T1071.001',
      },
      {
        name: 'LSASS Process Memory Dumping',
        description: 'Detects unauthorized attempts to access or dump the Local Security Authority Subsystem Service (LSASS) process.',
        severity: Severity.CRITICAL,
        ruleType: 'PATTERN',
        criteria: [
          { field: 'description', operator: 'CONTAINS', value: 'lsass' },
        ],
        mitreTactic: 'Credential Access',
        mitreTechnique: 'OS Credential Dumping: LSASS Memory',
        mitreTechniqueId: 'T1003.001',
      },
      {
        name: 'Ransomware Volume Shadow Copy Deletion',
        description: 'Detects execution of commands attempting to delete or inhibit system recovery volume shadow copies.',
        severity: Severity.CRITICAL,
        ruleType: 'PATTERN',
        criteria: [
          { field: 'description', operator: 'CONTAINS', value: 'vssadmin' },
        ],
        mitreTactic: 'Impact',
        mitreTechnique: 'Data Encrypted for Impact',
        mitreTechniqueId: 'T1486',
      },
    ];

    for (const rule of defaultRules) {
      await this.prisma.detectionRule.create({
        data: {
          organizationId,
          name: rule.name,
          description: rule.description,
          severity: rule.severity,
          ruleType: rule.ruleType,
          criteria: rule.criteria as any,
          mitreTactic: rule.mitreTactic,
          mitreTechnique: rule.mitreTechnique,
          mitreTechniqueId: rule.mitreTechniqueId,
          enabled: true,
        },
      });
    }
  }

  // ==========================================
  // Rules Management
  // ==========================================

  async findAllRules(organizationId: string): Promise<SharedDetectionRule[]> {
    await this.seedDefaultRulesIfEmpty(organizationId);

    const rules = await this.prisma.detectionRule.findMany({
      where: { organizationId },
      orderBy: { createdAt: 'desc' },
    });

    return rules.map((r) => this.mapToSharedRule(r));
  }

  async findRuleById(id: string, organizationId: string): Promise<SharedDetectionRule> {
    const rule = await this.prisma.detectionRule.findFirst({
      where: { id, organizationId },
    });

    if (!rule) {
      throw new NotFoundException(`Detection Rule "${id}" not found.`);
    }

    return this.mapToSharedRule(rule);
  }

  async createRule(
    dto: CreateRuleDto,
    organizationId: string,
    currentUser?: AuthenticatedUser,
  ): Promise<SharedDetectionRule> {
    // Validate MITRE technique if provided
    let techniqueName = dto.mitreTechnique;
    let tacticName = dto.mitreTactic;

    if (dto.mitreTechniqueId) {
      const tech = this.mitreService.getTechniqueById(dto.mitreTechniqueId);
      if (!tech) {
        throw new BadRequestException(
          `Invalid MITRE ATT&CK technique ID "${dto.mitreTechniqueId}". Must be an officially cataloged technique (e.g., T1059.001).`,
        );
      }
      techniqueName = tech.name;
      tacticName = tech.tactic;
    }

    const created = await this.prisma.detectionRule.create({
      data: {
        organizationId,
        name: dto.name,
        description: dto.description,
        severity: dto.severity || Severity.HIGH,
        ruleType: dto.ruleType || 'PATTERN',
        criteria: dto.criteria as any,
        mitreTactic: tacticName,
        mitreTechnique: techniqueName,
        mitreTechniqueId: dto.mitreTechniqueId ? dto.mitreTechniqueId.toUpperCase() : undefined,
        enabled: dto.enabled !== undefined ? dto.enabled : true,
      },
    });

    if (this.auditService) {
      await this.auditService.log({
        organizationId,
        userId: currentUser?.id,
        action: 'DETECTION_RULE_CREATE',
        entityType: 'DETECTION_RULE',
        entityId: created.id,
        details: { name: created.name, severity: created.severity, ruleType: created.ruleType },
      });
    }

    return this.mapToSharedRule(created);
  }

  async updateRule(
    id: string,
    dto: UpdateRuleDto,
    organizationId: string,
    currentUser?: AuthenticatedUser,
  ): Promise<SharedDetectionRule> {
    await this.findRuleById(id, organizationId);

    let techniqueName = dto.mitreTechnique;
    let tacticName = dto.mitreTactic;

    if (dto.mitreTechniqueId) {
      const tech = this.mitreService.getTechniqueById(dto.mitreTechniqueId);
      if (!tech) {
        throw new BadRequestException(
          `Invalid MITRE ATT&CK technique ID "${dto.mitreTechniqueId}". Must be an officially cataloged technique.`,
        );
      }
      techniqueName = tech.name;
      tacticName = tech.tactic;
    }

    const updated = await this.prisma.detectionRule.update({
      where: { id },
      data: {
        ...(dto.name && { name: dto.name }),
        ...(dto.description && { description: dto.description }),
        ...(dto.severity && { severity: dto.severity }),
        ...(dto.ruleType && { ruleType: dto.ruleType }),
        ...(dto.criteria && { criteria: dto.criteria as any }),
        ...(dto.mitreTechniqueId !== undefined && {
          mitreTechniqueId: dto.mitreTechniqueId ? dto.mitreTechniqueId.toUpperCase() : null,
          mitreTechnique: techniqueName,
          mitreTactic: tacticName,
        }),
        ...(dto.enabled !== undefined && { enabled: dto.enabled }),
      },
    });

    if (this.auditService) {
      await this.auditService.log({
        organizationId,
        userId: currentUser?.id,
        action: 'DETECTION_RULE_UPDATE',
        entityType: 'DETECTION_RULE',
        entityId: updated.id,
        details: { name: updated.name, enabled: updated.enabled },
      });
    }

    return this.mapToSharedRule(updated);
  }

  async toggleRule(id: string, organizationId: string, enabled?: boolean): Promise<SharedDetectionRule> {
    const existing = await this.findRuleById(id, organizationId);
    const newStatus = enabled !== undefined ? enabled : !existing.enabled;

    const updated = await this.prisma.detectionRule.update({
      where: { id },
      data: { enabled: newStatus },
    });

    return this.mapToSharedRule(updated);
  }

  async deleteRule(
    id: string,
    organizationId: string,
    currentUser?: AuthenticatedUser,
  ): Promise<{ success: boolean }> {
    await this.findRuleById(id, organizationId);

    await this.prisma.detectionRule.delete({
      where: { id },
    });

    if (this.auditService) {
      await this.auditService.log({
        organizationId,
        userId: currentUser?.id,
        action: 'DETECTION_RULE_DELETE',
        entityType: 'DETECTION_RULE',
        entityId: id,
      });
    }

    return { success: true };
  }

  // ==========================================
  // Alert Evaluation Engine & Finding Correlation
  // ==========================================

  /**
   * Evaluates an incoming security alert against detection rules and verified threat intel IOCs.
   * Produces correlated SecurityFinding records with explainable risk scores and suppresses duplicate alert storms.
   */
  async evaluateAlert(alert: PrismaAlert, organizationId: string): Promise<SharedSecurityFinding[]> {
    await this.seedDefaultRulesIfEmpty(organizationId);

    // 1. Fetch enabled detection rules
    const rules = await this.prisma.detectionRule.findMany({
      where: { organizationId, enabled: true },
    });

    // 2. Fetch active IOCs for this organization or global
    const activeIocs = await this.prisma.indicatorOfCompromise.findMany({
      where: {
        OR: [{ organizationId }, { organizationId: null }],
        isActive: true,
      },
    });

    const alertText = `${alert.title} ${alert.description} ${alert.source} ${JSON.stringify(alert.rawPayload || {})}`.toLowerCase();

    // Check direct IOC matches against alert text
    const matchedIocs = activeIocs.filter((ioc) =>
      alertText.includes(ioc.value.toLowerCase()),
    );

    const generatedFindings: SharedSecurityFinding[] = [];

    // 3. Evaluate each rule
    for (const rule of rules) {
      const criteria = (rule.criteria as any as DetectionRuleCriterion[]) || [];
      let ruleMatched = false;
      const matchedCriteriaNotes: string[] = [];

      if (rule.ruleType === 'IOC_MATCH') {
        // If IOC match rule, matches if any active IOC was found in alert, or if criteria match
        if (matchedIocs.length > 0) {
          ruleMatched = true;
          matchedCriteriaNotes.push(`Matched ${matchedIocs.length} verified IOC(s): ${matchedIocs.map((i) => i.value).join(', ')}`);
        }
      }

      if (!ruleMatched && criteria.length > 0) {
        // Evaluate all criteria (AND logic by default)
        let allCriteriaPass = true;
        for (const crit of criteria) {
          let targetVal: any;
          if (crit.field.startsWith('rawPayload.')) {
            targetVal = getNestedValue(alert.rawPayload, crit.field.replace('rawPayload.', ''));
          } else {
            targetVal = (alert as any)[crit.field];
          }

          const passed = evaluateCriterion(targetVal, crit.operator, crit.value);
          if (passed) {
            matchedCriteriaNotes.push(`Condition passed: ${crit.field} ${crit.operator} "${crit.value}"`);
          } else {
            allCriteriaPass = false;
            break;
          }
        }

        if (allCriteriaPass) {
          ruleMatched = true;
        }
      }

      if (ruleMatched) {
        // Deterministic fingerprint to prevent duplicate storm
        // Hash orgId + ruleId + alert.source + normalized title
        const fingerprintInput = `${organizationId}:${rule.id}:${alert.source}:${alert.title.toLowerCase().trim()}`;
        const fingerprint = crypto.createHash('sha256').update(fingerprintInput).digest('hex');

        // Check for recent existing finding with same fingerprint in the same org
        const existingFinding = await this.prisma.securityFinding.findFirst({
          where: {
            organizationId,
            fingerprint,
            status: { in: ['NEW', 'ANALYZED'] },
          },
        });

        if (existingFinding) {
          this.logger.debug(
            `Duplicate alert finding suppressed (fingerprint ${fingerprint.slice(0, 8)}). Updating timestamp.`,
          );
          // Increment evidence list or touch updatedAt
          const existingEvidence = (existingFinding.evidence as Record<string, any>) || {};
          const duplicateCount = (existingEvidence.duplicateCount || 1) + 1;
          const updatedAlertIds = Array.isArray(existingEvidence.alertIds)
            ? [...new Set([...existingEvidence.alertIds, alert.id])]
            : [existingFinding.alertId, alert.id].filter(Boolean);

          const updatedFinding = await this.prisma.securityFinding.update({
            where: { id: existingFinding.id },
            data: {
              updatedAt: new Date(),
              evidence: {
                ...existingEvidence,
                duplicateCount,
                alertIds: updatedAlertIds,
                lastSeenAt: new Date().toISOString(),
              },
            },
            include: { rule: true },
          });

          generatedFindings.push(this.mapToSharedFinding(updatedFinding));
          continue;
        }

        // Calculate explainable risk score
        const evidenceItems = [
          `Rule: ${rule.name}`,
          `Alert Source: ${alert.source}`,
          ...matchedCriteriaNotes,
          ...matchedIocs.map((ioc) => `Matched IOC [${ioc.type}] ${ioc.value} (Confidence: ${ioc.confidence || 0.8})`),
        ];

        const riskBreakdown = this.riskScoringService.calculate({
          severity: rule.severity as AlertSeverity,
          matchedIocs: matchedIocs.map((ioc) => ({
            id: ioc.id,
            type: ioc.type as any,
            value: ioc.value,
            confidence: ioc.confidence || 0.8,
            threatScore: ioc.threatScore || 60,
            severity: ioc.severity as any,
            createdAt: ioc.createdAt.toISOString(),
          })),
          mitreTactic: rule.mitreTactic || undefined,
          mitreTechniqueId: rule.mitreTechniqueId || undefined,
          evidenceItems,
        });

        // Create new SecurityFinding
        const finding = await this.prisma.securityFinding.create({
          data: {
            organizationId,
            ruleId: rule.id,
            title: `[Detection] ${rule.name}: ${alert.title}`,
            description: `${rule.description}\n\nTriggered by alert: "${alert.title}" from source "${alert.source}".`,
            severity: rule.severity,
            riskScore: riskBreakdown.totalScore,
            riskBreakdown: riskBreakdown as any,
            evidence: {
              alertId: alert.id,
              alertTitle: alert.title,
              alertSource: alert.source,
              matchedCriteria: matchedCriteriaNotes,
              matchedIocCount: matchedIocs.length,
              matchedIocValues: matchedIocs.map((i) => i.value),
              evidenceItems,
            },
            mitreTactic: rule.mitreTactic,
            mitreTechnique: rule.mitreTechnique,
            mitreTechniqueId: rule.mitreTechniqueId,
            alertId: alert.id,
            fingerprint,
            status: 'NEW',
          },
          include: { rule: true },
        });

        // Update rule trigger metrics
        await this.prisma.detectionRule.update({
          where: { id: rule.id },
          data: {
            lastTriggeredAt: new Date(),
            triggerCount: { increment: 1 },
          },
        });

        const sharedFinding = this.mapToSharedFinding(finding);

        if (this.eventsGateway) {
          this.eventsGateway.broadcastToOrg(organizationId, 'finding:created', sharedFinding);
        }

        if (this.auditService) {
          await this.auditService.log({
            organizationId,
            action: 'FINDING_GENERATED',
            entityType: 'FINDING',
            entityId: finding.id,
            details: {
              ruleName: rule.name,
              riskScore: riskBreakdown.totalScore,
              severity: finding.severity,
              mitreTechniqueId: rule.mitreTechniqueId,
            },
          });
        }

        generatedFindings.push(sharedFinding);
      }
    }

    return generatedFindings;
  }

  // ==========================================
  // Findings Management
  // ==========================================

  async findAllFindings(
    organizationId: string,
    filter?: { status?: string; severity?: string },
  ): Promise<SharedSecurityFinding[]> {
    const where: any = { organizationId };
    if (filter?.status) {
      where.status = filter.status;
    }
    if (filter?.severity) {
      where.severity = filter.severity;
    }

    const findings = await this.prisma.securityFinding.findMany({
      where,
      include: { rule: true },
      orderBy: { createdAt: 'desc' },
    });

    return findings.map((f) => this.mapToSharedFinding(f));
  }

  async findFindingById(id: string, organizationId: string): Promise<SharedSecurityFinding> {
    const finding = await this.prisma.securityFinding.findFirst({
      where: { id, organizationId },
      include: { rule: true },
    });

    if (!finding) {
      throw new NotFoundException(`Security Finding "${id}" not found.`);
    }

    return this.mapToSharedFinding(finding);
  }

  /**
   * Escalate/Promote a security finding into a full SOC Incident
   */
  async promoteToIncident(
    findingId: string,
    organizationId: string,
    currentUser?: AuthenticatedUser,
  ): Promise<SharedIncident> {
    const finding = await this.findFindingById(findingId, organizationId);

    // If finding already promoted to an incident, fetch and return that incident
    if (finding.status === 'PROMOTED' && finding.incidentId) {
      if (this.incidentsService) {
        return this.incidentsService.findById(finding.incidentId, organizationId);
      }
    }

    const escalationTitle = finding.title.startsWith('[Escalated]')
      ? finding.title
      : `[Escalated] ${finding.title}`;

    const escalationDesc = `${finding.description}\n\n---\n**Automated Escalation from Security Finding**\nFinding ID: \`${finding.id}\`\nCalculated Risk Score: **${finding.riskScore}/100** (${finding.severity})\nMITRE ATT&CK: ${finding.mitreTechniqueId || 'N/A'} - ${finding.mitreTechnique || 'N/A'} (${finding.mitreTactic || 'N/A'})`;

    let createdIncident: SharedIncident;

    if (this.incidentsService) {
      createdIncident = await this.incidentsService.create(
        {
          title: escalationTitle,
          description: escalationDesc,
          severity: finding.severity,
          status: 'NEW',
          sourceAlertIds: finding.alertId ? [finding.alertId] : undefined,
          mitigationSteps: [
            `Investigate correlated telemetry from rule "${finding.ruleName || 'Threat Detection'}".`,
            `Review MITRE ATT&CK ${finding.mitreTechniqueId || 'tactics'} implications.`,
            `Verify related host containment and review associated alert evidence.`,
          ],
        },
        organizationId,
        currentUser?.id,
        currentUser,
      );
    } else {
      // Fallback direct Prisma creation
      const inc = await this.prisma.incident.create({
        data: {
          organizationId,
          tenantId: organizationId,
          title: escalationTitle,
          description: escalationDesc,
          severity: finding.severity,
          status: 'NEW',
          mitigationSteps: [
            `Investigate correlated telemetry from rule "${finding.ruleName || 'Threat Detection'}".`,
            `Review MITRE ATT&CK ${finding.mitreTechniqueId || 'tactics'} implications.`,
          ],
          alerts: finding.alertId
            ? { connect: [{ id: finding.alertId }] }
            : undefined,
        },
        include: { iocs: true, alerts: true },
      });

      createdIncident = {
        id: inc.id,
        title: inc.title,
        description: inc.description,
        severity: inc.severity as AlertSeverity,
        status: inc.status as any,
        organizationId: inc.organizationId || inc.tenantId,
        sourceAlertIds: inc.alerts?.map((a) => a.id) || [],
        iocs: (inc.iocs || []).map((ioc) => ({
          id: ioc.id,
          type: ioc.type as any,
          value: ioc.value,
          confidence: ioc.confidence || 0.8,
          threatScore: ioc.threatScore || 60,
          severity: ioc.severity as any,
          createdAt: ioc.createdAt.toISOString(),
        })),
        createdAt: inc.createdAt.toISOString(),
        updatedAt: inc.updatedAt.toISOString(),
      };
    }

    // Update finding status to PROMOTED and link incidentId
    await this.prisma.securityFinding.update({
      where: { id: findingId },
      data: {
        status: 'PROMOTED',
        incidentId: createdIncident.id,
      },
    });

    if (this.eventsGateway) {
      this.eventsGateway.broadcastToOrg(organizationId, 'finding:updated', {
        ...finding,
        status: 'PROMOTED',
        incidentId: createdIncident.id,
      });
    }

    if (this.auditService) {
      await this.auditService.log({
        organizationId,
        userId: currentUser?.id,
        action: 'FINDING_PROMOTED',
        entityType: 'FINDING',
        entityId: findingId,
        details: { incidentId: createdIncident.id, title: escalationTitle },
      });
    }

    return createdIncident;
  }

  async dismissFinding(
    findingId: string,
    organizationId: string,
    reason?: string,
    currentUser?: AuthenticatedUser,
  ): Promise<SharedSecurityFinding> {
    await this.findFindingById(findingId, organizationId);

    const updated = await this.prisma.securityFinding.update({
      where: { id: findingId },
      data: {
        status: 'DISMISSED',
      },
      include: { rule: true },
    });

    if (this.eventsGateway) {
      this.eventsGateway.broadcastToOrg(organizationId, 'finding:updated', this.mapToSharedFinding(updated));
    }

    if (this.auditService) {
      await this.auditService.log({
        organizationId,
        userId: currentUser?.id,
        action: 'FINDING_DISMISSED',
        entityType: 'FINDING',
        entityId: findingId,
        details: { reason: reason || 'Analyst manual dismissal' },
      });
    }

    return this.mapToSharedFinding(updated);
  }
}
