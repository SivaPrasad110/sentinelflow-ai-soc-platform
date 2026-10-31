import {
  Injectable,
  NotFoundException,
  Logger,
  Optional,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import { EventsGateway } from '../events/events.gateway';
import { DetectionService } from '../detection/detection.service';
import { IngestAlertDto } from './dto/ingest-alert.dto';
import { UpdateAlertDto } from './dto/update-alert.dto';
import { SecurityAlert as SharedAlert, AlertSeverity } from '@sentinelflow/shared';
import { SecurityAlert as PrismaAlert } from '@prisma/client';

@Injectable()
export class AlertsService {
  private readonly logger = new Logger(AlertsService.name);

  constructor(
    private readonly prisma: PrismaService,
    @Optional() private readonly auditService?: AuditService,
    @Optional() private readonly eventsGateway?: EventsGateway,
    @Optional() private readonly detectionService?: DetectionService,
  ) {}

  private mapToSharedAlert(alert: PrismaAlert): SharedAlert {
    return {
      id: alert.id,
      title: alert.title,
      description: alert.description,
      severity: alert.severity as AlertSeverity,
      source: alert.source,
      organizationId: alert.organizationId || alert.tenantId,
      rawEvent: (alert.rawPayload as Record<string, unknown>) || undefined,
      detectedAt: alert.detectedAt.toISOString(),
      createdAt: alert.createdAt.toISOString(),
    };
  }

  async findAll(organizationId: string): Promise<SharedAlert[]> {
    const alerts = await this.prisma.securityAlert.findMany({
      where: {
        OR: [
          { organizationId },
          { tenantId: organizationId },
        ],
      },
      orderBy: { detectedAt: 'desc' },
    });
    return alerts.map((a) => this.mapToSharedAlert(a));
  }

  async findById(id: string, organizationId: string): Promise<SharedAlert> {
    const alert = await this.prisma.securityAlert.findFirst({
      where: {
        id,
        OR: [
          { organizationId },
          { tenantId: organizationId },
        ],
      },
    });

    if (!alert) {
      throw new NotFoundException(`Security Alert with ID "${id}" was not found in your organization.`);
    }

    return this.mapToSharedAlert(alert);
  }

  async ingest(dto: IngestAlertDto, organizationId: string): Promise<SharedAlert> {
    const alert = await this.prisma.securityAlert.create({
      data: {
        title: dto.title,
        description: dto.description,
        severity: dto.severity || 'MEDIUM',
        source: dto.source,
        organizationId,
        tenantId: organizationId,
        incidentId: dto.incidentId,
        rawPayload: (dto.rawPayload as any) || undefined,
        detectedAt: dto.detectedAt ? new Date(dto.detectedAt) : new Date(),
      },
    });

    if (this.auditService) {
      await this.auditService.log({
        organizationId,
        action: 'ALERT_CREATE',
        entityType: 'ALERT',
        entityId: alert.id,
        details: { title: alert.title, severity: alert.severity, source: alert.source },
      });
    }

    const shared = this.mapToSharedAlert(alert);
    if (this.eventsGateway) {
      this.eventsGateway.broadcastToOrg(organizationId, 'alert:created', shared);
    }

    // Evaluate detection rules and correlate findings
    if (this.detectionService) {
      try {
        await this.detectionService.evaluateAlert(alert, organizationId);
      } catch (err: any) {
        this.logger.error(`Error evaluating detection rules for alert ${alert.id}: ${err.message}`, err.stack);
      }
    }

    return shared;
  }

  async update(id: string, dto: UpdateAlertDto, organizationId: string): Promise<SharedAlert> {
    // Verify existence within authorized organization first to prevent IDOR
    await this.findById(id, organizationId);

    const updated = await this.prisma.securityAlert.update({
      where: { id },
      data: {
        ...(dto.title && { title: dto.title }),
        ...(dto.description && { description: dto.description }),
        ...(dto.severity && { severity: dto.severity }),
        ...(dto.incidentId !== undefined && { incidentId: dto.incidentId }),
      },
    });

    return this.mapToSharedAlert(updated);
  }
}
