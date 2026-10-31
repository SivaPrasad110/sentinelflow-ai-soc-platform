import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuditLogRecord } from '@sentinelflow/shared';

export interface CreateAuditLogParams {
  organizationId: string;
  userId?: string;
  userEmail?: string;
  action: string;
  entityType: string;
  entityId?: string;
  details?: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
}

@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Append-only audit logger.
   * Records are immutable and cannot be updated or deleted by anyone.
   */
  async log(params: CreateAuditLogParams): Promise<void> {
    try {
      await this.prisma.auditLog.create({
        data: {
          organizationId: params.organizationId,
          userId: params.userId || undefined,
          userEmail: params.userEmail || undefined,
          action: params.action,
          entityType: params.entityType,
          entityId: params.entityId || undefined,
          details: params.details as any,
          ipAddress: params.ipAddress || undefined,
          userAgent: params.userAgent ? params.userAgent.slice(0, 500) : undefined,
        },
      });
    } catch (err: any) {
      // Never let an audit logging failure crash the primary operation, but log heavily
      this.logger.error(`Failed to record audit log for action ${params.action}: ${err.message}`);
    }
  }

  /**
   * Retrieve immutable audit logs strictly scoped to the authorized organization.
   */
  async findByOrganization(
    organizationId: string,
    limit = 50,
    action?: string,
  ): Promise<AuditLogRecord[]> {
    const records = await this.prisma.auditLog.findMany({
      where: {
        organizationId,
        ...(action ? { action } : {}),
      },
      orderBy: { createdAt: 'desc' },
      take: Math.min(limit, 100),
    });

    return records.map((r) => ({
      id: r.id,
      organizationId: r.organizationId,
      userId: r.userId || undefined,
      userEmail: r.userEmail || undefined,
      action: r.action,
      entityType: r.entityType,
      entityId: r.entityId || undefined,
      details: (r.details as Record<string, unknown>) || undefined,
      ipAddress: r.ipAddress || undefined,
      userAgent: r.userAgent || undefined,
      createdAt: r.createdAt.toISOString(),
    }));
  }
}
