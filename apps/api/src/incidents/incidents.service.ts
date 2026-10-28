import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  Logger,
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
} from '@sentinelflow/shared';
import { Incident as PrismaIncident, IndicatorOfCompromise as PrismaIOC, User as PrismaUser, SecurityAlert as PrismaAlert } from '@prisma/client';

type IncidentWithRelations = PrismaIncident & {
  iocs: PrismaIOC[];
  alerts?: PrismaAlert[];
  assignedTo?: PrismaUser | null;
};

@Injectable()
export class IncidentsService {
  private readonly logger = new Logger(IncidentsService.name);
  private readonly defaultTenant = 'default-tenant';

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Verify tenant access authorization before querying or mutating multi-tenant data.
   */
  private verifyTenantAccess(requestedTenantId?: string, userTenantId: string = this.defaultTenant): string {
    const targetTenant = requestedTenantId || userTenantId;
    if (targetTenant !== userTenantId && userTenantId !== 'system-admin-tenant') {
      this.logger.warn(`Tenant authorization failure: attempted access to "${targetTenant}" from "${userTenantId}"`);
      throw new ForbiddenException(`Unauthorized: cross-tenant access to "${targetTenant}" is denied.`);
    }
    return targetTenant;
  }

  private mapToSharedIncident(incident: IncidentWithRelations): SharedIncident {
    const iocs: SharedIOC[] = (incident.iocs || []).map((ioc) => ({
      id: ioc.id,
      type: ioc.type as SharedIOC['type'],
      value: ioc.value,
      threatScore: ioc.threatScore !== null ? ioc.threatScore : undefined,
      enrichedData: (ioc.enrichedData as Record<string, unknown>) || undefined,
      createdAt: ioc.createdAt.toISOString(),
    }));

    return {
      id: incident.id,
      title: incident.title,
      description: incident.description,
      severity: incident.severity as AlertSeverity,
      status: incident.status as SharedIncidentStatus,
      sourceAlertIds: (incident.alerts || []).map((a) => a.id),
      iocs,
      aiAnalysis: (incident.aiAnalysis as unknown as AIAnalysisResult) || undefined,
      assignedTo: incident.assignedTo ? incident.assignedTo.name : undefined,
      createdAt: incident.createdAt.toISOString(),
      updatedAt: incident.updatedAt.toISOString(),
    };
  }

  async findAll(tenantId?: string): Promise<SharedIncident[]> {
    const authorizedTenant = this.verifyTenantAccess(tenantId);
    const incidents = await this.prisma.incident.findMany({
      where: { tenantId: authorizedTenant },
      include: {
        iocs: true,
        alerts: true,
        assignedTo: true,
      },
      orderBy: { createdAt: 'desc' },
    });

    return incidents.map((inc) => this.mapToSharedIncident(inc));
  }

  async findById(id: string, tenantId?: string): Promise<SharedIncident> {
    const authorizedTenant = this.verifyTenantAccess(tenantId);
    const incident = await this.prisma.incident.findFirst({
      where: { id, tenantId: authorizedTenant },
      include: {
        iocs: true,
        alerts: true,
        assignedTo: true,
      },
    });

    if (!incident) {
      throw new NotFoundException(`Incident with ID "${id}" was not found.`);
    }

    return this.mapToSharedIncident(incident);
  }

  async create(dto: CreateIncidentDto, tenantId?: string): Promise<SharedIncident> {
    const authorizedTenant = this.verifyTenantAccess(dto.tenantId || tenantId);

    const created = await this.prisma.incident.create({
      data: {
        title: dto.title,
        description: dto.description,
        severity: dto.severity || 'MEDIUM',
        status: dto.status || 'NEW',
        tenantId: authorizedTenant,
        assignedToId: dto.assignedToId,
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
      },
    });

    return this.mapToSharedIncident(created);
  }

  async update(id: string, dto: UpdateIncidentDto, tenantId?: string): Promise<SharedIncident> {
    const authorizedTenant = this.verifyTenantAccess(tenantId);

    // Verify existence
    await this.findById(id, authorizedTenant);

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
      },
    });

    return this.mapToSharedIncident(updated);
  }

  async delete(id: string, tenantId?: string): Promise<{ success: boolean; id: string }> {
    const authorizedTenant = this.verifyTenantAccess(tenantId);
    await this.findById(id, authorizedTenant);

    await this.prisma.incident.delete({
      where: { id },
    });

    return { success: true, id };
  }
}
