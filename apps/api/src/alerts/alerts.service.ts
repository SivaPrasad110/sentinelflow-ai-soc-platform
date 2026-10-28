import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  Logger,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { IngestAlertDto } from './dto/ingest-alert.dto';
import { UpdateAlertDto } from './dto/update-alert.dto';
import { SecurityAlert as SharedAlert, AlertSeverity } from '@sentinelflow/shared';
import { SecurityAlert as PrismaAlert } from '@prisma/client';

@Injectable()
export class AlertsService {
  private readonly logger = new Logger(AlertsService.name);
  private readonly defaultTenant = 'default-tenant';

  constructor(private readonly prisma: PrismaService) {}

  private verifyTenantAccess(requestedTenantId?: string, userTenantId: string = this.defaultTenant): string {
    const targetTenant = requestedTenantId || userTenantId;
    if (targetTenant !== userTenantId && userTenantId !== 'system-admin-tenant') {
      this.logger.warn(`Tenant authorization failure: attempted access to "${targetTenant}" from "${userTenantId}"`);
      throw new ForbiddenException(`Unauthorized: cross-tenant access to "${targetTenant}" is denied.`);
    }
    return targetTenant;
  }

  private mapToSharedAlert(alert: PrismaAlert): SharedAlert {
    return {
      id: alert.id,
      title: alert.title,
      description: alert.description,
      severity: alert.severity as AlertSeverity,
      source: alert.source,
      rawEvent: (alert.rawPayload as Record<string, unknown>) || undefined,
      detectedAt: alert.detectedAt.toISOString(),
      createdAt: alert.createdAt.toISOString(),
    };
  }

  async findAll(tenantId?: string): Promise<SharedAlert[]> {
    const authorizedTenant = this.verifyTenantAccess(tenantId);
    const alerts = await this.prisma.securityAlert.findMany({
      where: { tenantId: authorizedTenant },
      orderBy: { detectedAt: 'desc' },
    });
    return alerts.map((a) => this.mapToSharedAlert(a));
  }

  async findById(id: string, tenantId?: string): Promise<SharedAlert> {
    const authorizedTenant = this.verifyTenantAccess(tenantId);
    const alert = await this.prisma.securityAlert.findFirst({
      where: { id, tenantId: authorizedTenant },
    });

    if (!alert) {
      throw new NotFoundException(`Security Alert with ID "${id}" was not found.`);
    }

    return this.mapToSharedAlert(alert);
  }

  async ingest(dto: IngestAlertDto, tenantId?: string): Promise<SharedAlert> {
    const authorizedTenant = this.verifyTenantAccess(dto.tenantId || tenantId);

    const alert = await this.prisma.securityAlert.create({
      data: {
        title: dto.title,
        description: dto.description,
        severity: dto.severity || 'MEDIUM',
        source: dto.source,
        tenantId: authorizedTenant,
        incidentId: dto.incidentId,
        rawPayload: (dto.rawPayload as any) || undefined,
        detectedAt: dto.detectedAt ? new Date(dto.detectedAt) : new Date(),
      },
    });

    return this.mapToSharedAlert(alert);
  }

  async update(id: string, dto: UpdateAlertDto, tenantId?: string): Promise<SharedAlert> {
    const authorizedTenant = this.verifyTenantAccess(tenantId);
    await this.findById(id, authorizedTenant);

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
