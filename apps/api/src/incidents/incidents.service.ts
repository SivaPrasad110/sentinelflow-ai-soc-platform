import {
  Injectable,
  NotFoundException,
  BadRequestException,
  Logger,
  Optional,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateIncidentDto } from './dto/create-incident.dto';
import { UpdateIncidentDto } from './dto/update-incident.dto';
import {
  Incident as SharedIncident,
  AlertSeverity,
  IncidentStatus as SharedIncidentStatus,
  IndicatorOfCompromise as SharedIOC,
  AIAnalysisResult,
  IncidentAnalysisRecord,
  AnalysisStatus,
  IncidentTimelineEventRecord,
  OrgMember,
} from '@sentinelflow/shared';
import {
  Incident as PrismaIncident,
  IndicatorOfCompromise as PrismaIOC,
  User as PrismaUser,
  SecurityAlert as PrismaAlert,
  IncidentAnalysis as PrismaIncidentAnalysis,
  IncidentTimelineEvent as PrismaTimelineEvent,
} from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { EventsGateway } from '../events/events.gateway';
import { AuthenticatedUser } from '../auth/decorators/current-user.decorator';

type IncidentWithRelations = PrismaIncident & {
  iocs: PrismaIOC[];
  alerts?: PrismaAlert[];
  assignedTo?: PrismaUser | null;
  analyses?: PrismaIncidentAnalysis[];
  timelineEvents?: PrismaTimelineEvent[];
};

@Injectable()
export class IncidentsService {
  private readonly logger = new Logger(IncidentsService.name);

  constructor(
    private readonly prisma: PrismaService,
    @Optional() private readonly auditService?: AuditService,
    @Optional() private readonly eventsGateway?: EventsGateway,
  ) {}

  private mapToSharedIncident(incident: IncidentWithRelations): SharedIncident {
    const iocs: SharedIOC[] = (incident.iocs || []).map((ioc) => ({
      id: ioc.id,
      type: ioc.type as SharedIOC['type'],
      value: ioc.value,
      threatScore: ioc.threatScore !== null ? ioc.threatScore : undefined,
      enrichedData: (ioc.enrichedData as Record<string, unknown>) || undefined,
      createdAt: ioc.createdAt.toISOString(),
    }));

    const analyses: IncidentAnalysisRecord[] | undefined = incident.analyses?.map((a) => ({
      id: a.id,
      incidentId: a.incidentId,
      organizationId: a.organizationId,
      status: a.status as AnalysisStatus,
      eventId: a.eventId,
      workflowId: a.workflowId || undefined,
      executionId: a.executionId || undefined,
      model: a.model || undefined,
      summary: a.summary || undefined,
      severityAssessment: a.severityAssessment || undefined,
      confidence: a.confidence !== null ? a.confidence : undefined,
      evidence: a.evidence || [],
      potentialImpact: a.potentialImpact || undefined,
      recommendedActions: a.recommendedActions || [],
      missingInformation: a.missingInformation || [],
      requiresHumanReview: a.requiresHumanReview,
      errorMessage: a.errorMessage || undefined,
      durationMs: a.durationMs || undefined,
      triggeredById: a.triggeredById || undefined,
      createdAt: a.createdAt.toISOString(),
      completedAt: a.completedAt ? a.completedAt.toISOString() : undefined,
    }));

    const timeline: IncidentTimelineEventRecord[] | undefined = incident.timelineEvents?.map((t) => ({
      id: t.id,
      incidentId: t.incidentId,
      organizationId: t.organizationId,
      type: t.type as IncidentTimelineEventRecord['type'],
      message: t.message,
      userId: t.userId || undefined,
      userName: t.userName || undefined,
      userEmail: t.userEmail || undefined,
      metadata: (t.metadata as Record<string, unknown>) || undefined,
      createdAt: t.createdAt.toISOString(),
    }));

    return {
      id: incident.id,
      title: incident.title,
      description: incident.description,
      severity: incident.severity as AlertSeverity,
      status: incident.status as SharedIncidentStatus,
      organizationId: incident.organizationId || incident.tenantId,
      sourceAlertIds: (incident.alerts || []).map((a) => a.id),
      iocs,
      aiAnalysis: (incident.aiAnalysis as unknown as AIAnalysisResult) || undefined,
      analyses,
      timeline,
      assignedTo: incident.assignedTo ? incident.assignedTo.name : undefined,
      assignedToId: incident.assignedToId || undefined,
      assignedToName: incident.assignedTo ? incident.assignedTo.name : undefined,
      assignedToEmail: incident.assignedTo ? incident.assignedTo.email : undefined,
      acknowledgedAt: incident.acknowledgedAt ? incident.acknowledgedAt.toISOString() : undefined,
      resolvedAt: incident.resolvedAt ? incident.resolvedAt.toISOString() : undefined,
      closedAt: incident.closedAt ? incident.closedAt.toISOString() : undefined,
      createdAt: incident.createdAt.toISOString(),
      updatedAt: incident.updatedAt.toISOString(),
    };
  }

  async findAll(organizationId: string): Promise<SharedIncident[]> {
    const incidents = await this.prisma.incident.findMany({
      where: {
        OR: [
          { organizationId },
          { tenantId: organizationId },
        ],
      },
      include: {
        iocs: true,
        alerts: true,
        assignedTo: true,
        analyses: {
          orderBy: { createdAt: 'desc' },
        },
        timelineEvents: {
          orderBy: { createdAt: 'asc' },
        },
      },
      orderBy: { createdAt: 'desc' },
    });

    return incidents.map((inc) => this.mapToSharedIncident(inc));
  }

  async findById(id: string, organizationId: string): Promise<SharedIncident> {
    const incident = await this.prisma.incident.findFirst({
      where: {
        id,
        OR: [
          { organizationId },
          { tenantId: organizationId },
        ],
      },
      include: {
        iocs: true,
        alerts: true,
        assignedTo: true,
        analyses: {
          orderBy: { createdAt: 'desc' },
        },
        timelineEvents: {
          orderBy: { createdAt: 'asc' },
        },
      },
    });

    if (!incident) {
      throw new NotFoundException(`Incident with ID "${id}" was not found in your organization.`);
    }

    return this.mapToSharedIncident(incident);
  }

  async create(
    dto: CreateIncidentDto,
    organizationId: string,
    creatorUserId?: string,
    currentUser?: AuthenticatedUser,
  ): Promise<SharedIncident> {
    const created = await this.prisma.incident.create({
      data: {
        title: dto.title,
        description: dto.description,
        severity: dto.severity || 'MEDIUM',
        status: dto.status || 'NEW',
        organizationId,
        tenantId: organizationId,
        assignedToId: dto.assignedToId || creatorUserId,
        mitigationSteps: dto.mitigationSteps || [],
        aiAnalysis: (dto.aiAnalysis as any) || undefined,
        iocs: dto.iocs && dto.iocs.length > 0
          ? {
              create: dto.iocs.map((ioc) => ({
                type: ioc.type,
                value: ioc.value,
                threatScore: ioc.threatScore,
              })),
            }
          : undefined,
        alerts: dto.sourceAlertIds && dto.sourceAlertIds.length > 0
          ? {
              connect: dto.sourceAlertIds.map((alertId) => ({ id: alertId })),
            }
          : undefined,
      },
      include: {
        iocs: true,
        alerts: true,
        assignedTo: true,
        analyses: {
          orderBy: { createdAt: 'desc' },
        },
        timelineEvents: {
          orderBy: { createdAt: 'asc' },
        },
      },
    });

    // Add initial timeline event
    const initialTimeline = this.prisma.incidentTimelineEvent
      ? await this.prisma.incidentTimelineEvent.create({
          data: {
            incidentId: created.id,
            organizationId,
            type: 'STATUS_CHANGE',
            message: `Incident created with ${created.severity} severity by ${currentUser?.email || 'system'}`,
            userId: currentUser?.id,
            userName: currentUser?.name,
            userEmail: currentUser?.email,
          },
        })
      : null;

    // Log security audit record
    if (this.auditService) {
      await this.auditService.log({
        organizationId,
        userId: currentUser?.id || creatorUserId,
        userEmail: currentUser?.email,
        action: 'INCIDENT_CREATE',
        entityType: 'INCIDENT',
        entityId: created.id,
        details: {
          title: created.title,
          severity: created.severity,
          assignedToId: created.assignedToId,
        },
      });
    }

    const shared = this.mapToSharedIncident(created);
    if (this.eventsGateway) {
      this.eventsGateway.broadcastToOrg(organizationId, 'incident:created', shared);
      if (initialTimeline) {
        this.eventsGateway.broadcastToOrg(organizationId, 'incident:timeline_event', {
          id: initialTimeline.id,
          incidentId: created.id,
          organizationId,
          type: 'STATUS_CHANGE',
          message: initialTimeline.message,
          userId: currentUser?.id,
          userName: currentUser?.name,
          userEmail: currentUser?.email,
          createdAt: initialTimeline.createdAt.toISOString(),
        });
      }
    }

    return shared;
  }

  async update(
    id: string,
    dto: UpdateIncidentDto,
    organizationId: string,
    currentUser?: AuthenticatedUser,
  ): Promise<SharedIncident> {
    // Verify existence within authorized organization first to prevent IDOR
    const existing = await this.findById(id, organizationId);

    // Calculate acknowledgment or resolution timestamps
    let acknowledgedAt: Date | undefined = undefined;
    let resolvedAt: Date | undefined = undefined;
    let closedAt: Date | undefined = undefined;

    if (dto.status) {
      if (existing.status === 'NEW' && dto.status !== 'NEW' && !existing.acknowledgedAt) {
        acknowledgedAt = new Date();
      }
      if ((dto.status === 'RESOLVED') && !existing.resolvedAt) {
        resolvedAt = new Date();
      }
      if (dto.status === 'CLOSED' && !existing.closedAt) {
        closedAt = new Date();
      }
    }

    const updated = await this.prisma.incident.update({
      where: { id },
      data: {
        ...(dto.title && { title: dto.title }),
        ...(dto.description && { description: dto.description }),
        ...(dto.severity && { severity: dto.severity }),
        ...(dto.status && { status: dto.status }),
        ...(dto.assignedToId && { assignedToId: dto.assignedToId }),
        ...(dto.mitigationSteps && { mitigationSteps: dto.mitigationSteps }),
        ...(dto.aiAnalysis && { aiAnalysis: dto.aiAnalysis as any }),
        ...(acknowledgedAt && { acknowledgedAt }),
        ...(resolvedAt && { resolvedAt }),
        ...(closedAt && { closedAt }),
        ...(dto.iocs && dto.iocs.length > 0 && {
          iocs: {
            create: dto.iocs.map((ioc) => ({
              type: ioc.type,
              value: ioc.value,
              threatScore: ioc.threatScore,
            })),
          },
        }),
      },
      include: {
        iocs: true,
        alerts: true,
        assignedTo: true,
        analyses: {
          orderBy: { createdAt: 'desc' },
        },
        timelineEvents: {
          orderBy: { createdAt: 'asc' },
        },
      },
    });

    // Add timeline record if status or severity changed
    if (dto.status && dto.status !== existing.status) {
      const timelineEvent = this.prisma.incidentTimelineEvent
        ? await this.prisma.incidentTimelineEvent.create({
            data: {
              incidentId: id,
              organizationId,
              type: 'STATUS_CHANGE',
              message: `Status transitioned from ${existing.status} to ${dto.status} by ${currentUser?.email || 'analyst'}`,
              userId: currentUser?.id,
              userName: currentUser?.name,
              userEmail: currentUser?.email,
              metadata: { previousStatus: existing.status, newStatus: dto.status },
            },
          })
        : null;

      if (timelineEvent && this.eventsGateway) {
        this.eventsGateway.broadcastToOrg(organizationId, 'incident:timeline_event', {
          id: timelineEvent.id,
          incidentId: id,
          organizationId,
          type: 'STATUS_CHANGE',
          message: timelineEvent.message,
          userId: currentUser?.id,
          userName: currentUser?.name,
          userEmail: currentUser?.email,
          createdAt: timelineEvent.createdAt.toISOString(),
        });
      }
    }

    // Record audit log
    if (this.auditService) {
      await this.auditService.log({
        organizationId,
        userId: currentUser?.id,
        userEmail: currentUser?.email,
        action: 'INCIDENT_UPDATE',
        entityType: 'INCIDENT',
        entityId: id,
        details: {
          updates: dto,
          previousStatus: existing.status,
        },
      });
    }

    const shared = this.mapToSharedIncident(updated);
    if (this.eventsGateway) {
      this.eventsGateway.broadcastToOrg(organizationId, 'incident:updated', shared);
    }
    return shared;
  }

  async assign(
    id: string,
    assignedToId: string | null | undefined,
    organizationId: string,
    currentUser: AuthenticatedUser,
  ): Promise<SharedIncident> {
    const existing = await this.prisma.incident.findFirst({
      where: {
        id,
        OR: [{ organizationId }, { tenantId: organizationId }],
      },
      include: { assignedTo: true },
    });

    if (!existing) {
      throw new NotFoundException(`Incident "${id}" was not found in your organization.`);
    }

    let assignedUser: PrismaUser | null = null;
    if (assignedToId) {
      // Verify user exists and belongs to the same organization
      const membership = await this.prisma.organizationMembership.findFirst({
        where: {
          userId: assignedToId,
          organizationId,
        },
        include: { user: true },
      });

      if (!membership || !membership.user) {
        throw new BadRequestException(`Target user "${assignedToId}" is not a member of this organization.`);
      }
      assignedUser = membership.user;
    }

    // Auto-acknowledge if incident was in NEW state
    const autoAcknowledge = existing.status === 'NEW';
    const newStatus = autoAcknowledge ? 'TRIAGED' : existing.status;
    const acknowledgedAt = autoAcknowledge && !existing.acknowledgedAt ? new Date() : existing.acknowledgedAt;

    const updated = await this.prisma.incident.update({
      where: { id },
      data: {
        assignedToId: assignedToId || null,
        status: newStatus,
        acknowledgedAt,
      },
      include: {
        iocs: true,
        alerts: true,
        assignedTo: true,
        analyses: { orderBy: { createdAt: 'desc' } },
        timelineEvents: { orderBy: { createdAt: 'asc' } },
      },
    });

    const assignmentMessage = assignedUser
      ? `Incident assigned to ${assignedUser.name} (${assignedUser.email}) by ${currentUser.email}`
      : `Incident unassigned by ${currentUser.email}`;

    const timelineEvent = await this.prisma.incidentTimelineEvent.create({
      data: {
        incidentId: id,
        organizationId,
        type: 'ASSIGNMENT',
        message: assignmentMessage,
        userId: currentUser.id,
        userName: currentUser.name,
        userEmail: currentUser.email,
        metadata: {
          previousAssignedToId: existing.assignedToId,
          newAssignedToId: assignedToId || null,
        },
      },
    });

    if (this.auditService) {
      await this.auditService.log({
        organizationId,
        userId: currentUser.id,
        userEmail: currentUser.email,
        action: 'INCIDENT_ASSIGN',
        entityType: 'INCIDENT',
        entityId: id,
        details: {
          previousAssignedToId: existing.assignedToId,
          newAssignedToId: assignedToId || null,
          assignedToName: assignedUser?.name || null,
        },
      });
    }

    const shared = this.mapToSharedIncident(updated);
    if (this.eventsGateway) {
      this.eventsGateway.broadcastToOrg(organizationId, 'incident:assigned', {
        incidentId: id,
        assignedToId: assignedToId || null,
        assignedToName: assignedUser?.name,
      });
      this.eventsGateway.broadcastToOrg(organizationId, 'incident:updated', shared);
      this.eventsGateway.broadcastToOrg(organizationId, 'incident:timeline_event', {
        id: timelineEvent.id,
        incidentId: id,
        organizationId,
        type: 'ASSIGNMENT',
        message: assignmentMessage,
        userId: currentUser.id,
        userName: currentUser.name,
        userEmail: currentUser.email,
        createdAt: timelineEvent.createdAt.toISOString(),
      });
    }

    return shared;
  }

  async addComment(
    id: string,
    comment: string,
    organizationId: string,
    currentUser: AuthenticatedUser,
  ): Promise<IncidentTimelineEventRecord> {
    await this.findById(id, organizationId);

    const event = await this.prisma.incidentTimelineEvent.create({
      data: {
        incidentId: id,
        organizationId,
        type: 'COMMENT',
        message: comment.trim(),
        userId: currentUser.id,
        userName: currentUser.name,
        userEmail: currentUser.email,
      },
    });

    if (this.auditService) {
      await this.auditService.log({
        organizationId,
        userId: currentUser.id,
        userEmail: currentUser.email,
        action: 'COMMENT_CREATE',
        entityType: 'INCIDENT',
        entityId: id,
        details: { commentLength: comment.length },
      });
    }

    const record: IncidentTimelineEventRecord = {
      id: event.id,
      incidentId: id,
      organizationId,
      type: 'COMMENT',
      message: event.message,
      userId: currentUser.id,
      userName: currentUser.name,
      userEmail: currentUser.email,
      createdAt: event.createdAt.toISOString(),
    };

    if (this.eventsGateway) {
      this.eventsGateway.broadcastToOrg(organizationId, 'incident:timeline_event', record);
    }
    return record;
  }

  async getTimeline(id: string, organizationId: string): Promise<IncidentTimelineEventRecord[]> {
    await this.findById(id, organizationId);

    const events = await this.prisma.incidentTimelineEvent.findMany({
      where: {
        incidentId: id,
        organizationId,
      },
      orderBy: { createdAt: 'asc' },
    });

    return events.map((e) => ({
      id: e.id,
      incidentId: e.incidentId,
      organizationId: e.organizationId,
      type: e.type as IncidentTimelineEventRecord['type'],
      message: e.message,
      userId: e.userId || undefined,
      userName: e.userName || undefined,
      userEmail: e.userEmail || undefined,
      metadata: (e.metadata as Record<string, unknown>) || undefined,
      createdAt: e.createdAt.toISOString(),
    }));
  }

  async getOrgMembers(organizationId: string): Promise<OrgMember[]> {
    const memberships = await this.prisma.organizationMembership.findMany({
      where: { organizationId },
      include: { user: true },
      orderBy: { user: { name: 'asc' } },
    });

    return memberships.map((m) => ({
      id: m.id,
      userId: m.userId,
      name: m.user.name,
      email: m.user.email,
      role: m.role as OrgMember['role'],
    }));
  }

  async delete(
    id: string,
    organizationId: string,
    currentUser?: AuthenticatedUser,
  ): Promise<{ success: boolean; id: string }> {
    // Verify existence in authorized organization
    await this.findById(id, organizationId);

    await this.prisma.incident.delete({
      where: { id },
    });

    if (this.auditService) {
      await this.auditService.log({
        organizationId,
        userId: currentUser?.id,
        userEmail: currentUser?.email,
        action: 'INCIDENT_DELETE',
        entityType: 'INCIDENT',
        entityId: id,
      });
    }

    if (this.eventsGateway) {
      this.eventsGateway.broadcastToOrg(organizationId, 'incident:deleted', { id });
    }
    return { success: true, id };
  }
}
