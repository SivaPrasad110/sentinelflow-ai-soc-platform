import {
  Injectable,
  NotFoundException,
  BadRequestException,
  Logger,
  Optional,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import { EventsGateway } from '../events/events.gateway';
import { CreateIocDto } from './dto/create-ioc.dto';
import { UpdateIocDto } from './dto/update-ioc.dto';
import { QueryIocDto } from './dto/query-ioc.dto';
import {
  IndicatorOfCompromise as SharedIOC,
  IOCType,
  AlertSeverity,
} from '@sentinelflow/shared';
import { IndicatorOfCompromise as PrismaIOC } from '@prisma/client';
import { AuthenticatedUser } from '../auth/decorators/current-user.decorator';

@Injectable()
export class IocService {
  private readonly logger = new Logger(IocService.name);

  constructor(
    private readonly prisma: PrismaService,
    @Optional() private readonly auditService?: AuditService,
    @Optional() private readonly eventsGateway?: EventsGateway,
  ) {}

  /**
   * Validate IOC format based on its declared type
   */
  validateIocFormat(type: IOCType, value: string): boolean {
    const val = value.trim();
    switch (type) {
      case 'IP': {
        const ipv4Regex =
          /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const ipv6Regex =
          /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
        return ipv4Regex.test(val) || ipv6Regex.test(val);
      }
      case 'DOMAIN': {
        const domainRegex =
          /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
        return domainRegex.test(val);
      }
      case 'URL': {
        try {
          const u = new URL(val);
          return u.protocol === 'http:' || u.protocol === 'https:';
        } catch {
          return false;
        }
      }
      case 'HASH_SHA256': {
        return /^[a-fA-F0-9]{64}$/.test(val);
      }
      case 'HASH_MD5': {
        return /^[a-fA-F0-9]{32}$/.test(val);
      }
      case 'EMAIL': {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val);
      }
      default:
        return false;
    }
  }

  private mapToSharedIoc(ioc: PrismaIOC): SharedIOC {
    return {
      id: ioc.id,
      type: ioc.type as IOCType,
      value: ioc.value,
      threatScore: ioc.threatScore || undefined,
      confidence: ioc.confidence || undefined,
      severity: ioc.severity as AlertSeverity,
      source: ioc.source || undefined,
      description: ioc.description || undefined,
      organizationId: ioc.organizationId || undefined,
      incidentId: ioc.incidentId || undefined,
      firstSeen: ioc.firstSeen?.toISOString(),
      lastSeen: ioc.lastSeen?.toISOString(),
      tags: ioc.tags || [],
      mitreTactics: ioc.mitreTactics || [],
      mitreTechniques: ioc.mitreTechniques || [],
      isActive: ioc.isActive,
      rawFeedData: (ioc.rawFeedData as Record<string, unknown>) || undefined,
      enrichedData: (ioc.enrichedData as Record<string, unknown>) || undefined,
      createdAt: ioc.createdAt.toISOString(),
      updatedAt: ioc.updatedAt?.toISOString(),
    };
  }

  /**
   * Search and filter IOCs scoped strictly to authorized organization
   */
  async findAll(organizationId: string, queryDto: QueryIocDto): Promise<SharedIOC[]> {
    const { query, type, severity, source, isActive, limit = 50 } = queryDto;

    const where: any = {
      organizationId,
      ...(type && { type }),
      ...(severity && { severity }),
      ...(source && { source: { contains: source, mode: 'insensitive' } }),
      ...(isActive !== undefined && { isActive }),
    };

    if (query) {
      where.OR = [
        { value: { contains: query, mode: 'insensitive' } },
        { description: { contains: query, mode: 'insensitive' } },
        { tags: { has: query } },
      ];
    }

    const iocs = await this.prisma.indicatorOfCompromise.findMany({
      where,
      orderBy: { updatedAt: 'desc' },
      take: Math.min(limit, 100),
    });

    return iocs.map((i) => this.mapToSharedIoc(i));
  }

  /**
   * Get IOC by ID within organization
   */
  async findById(id: string, organizationId: string): Promise<SharedIOC> {
    const ioc = await this.prisma.indicatorOfCompromise.findFirst({
      where: {
        id,
        organizationId,
      },
    });

    if (!ioc) {
      throw new NotFoundException(`Indicator of Compromise with ID "${id}" was not found.`);
    }

    return this.mapToSharedIoc(ioc);
  }

  /**
   * Create or ingest an IOC
   */
  async create(
    dto: CreateIocDto,
    organizationId: string,
    currentUser?: AuthenticatedUser,
  ): Promise<SharedIOC> {
    if (!this.validateIocFormat(dto.type as IOCType, dto.value)) {
      throw new BadRequestException(
        `Invalid ${dto.type} indicator format: "${dto.value}". Please supply a valid value.`,
      );
    }

    // Check if indicator already exists for this organization
    const existing = await this.prisma.indicatorOfCompromise.findFirst({
      where: {
        value: dto.value.trim(),
        type: dto.type,
        organizationId,
      },
    });

    let iocRecord: PrismaIOC;

    if (existing) {
      // Deduplicate: update last seen and metadata
      iocRecord = await this.prisma.indicatorOfCompromise.update({
        where: { id: existing.id },
        data: {
          lastSeen: new Date(),
          threatScore: dto.threatScore ?? existing.threatScore,
          confidence: dto.confidence ?? existing.confidence,
          severity: dto.severity ?? existing.severity,
          description: dto.description ?? existing.description,
          tags: Array.from(new Set([...(existing.tags || []), ...(dto.tags || [])])),
          mitreTactics: Array.from(
            new Set([...(existing.mitreTactics || []), ...(dto.mitreTactics || [])]),
          ),
          mitreTechniques: Array.from(
            new Set([...(existing.mitreTechniques || []), ...(dto.mitreTechniques || [])]),
          ),
          isActive: dto.isActive ?? existing.isActive,
        },
      });
    } else {
      iocRecord = await this.prisma.indicatorOfCompromise.create({
        data: {
          type: dto.type,
          value: dto.value.trim(),
          threatScore: dto.threatScore ?? 50.0,
          confidence: dto.confidence ?? 0.8,
          severity: dto.severity || 'MEDIUM',
          source: dto.source || 'MANUAL',
          description: dto.description,
          organizationId,
          incidentId: dto.incidentId,
          firstSeen: new Date(),
          lastSeen: new Date(),
          tags: dto.tags || [],
          mitreTactics: dto.mitreTactics || [],
          mitreTechniques: dto.mitreTechniques || [],
          isActive: dto.isActive !== undefined ? dto.isActive : true,
        },
      });
    }

    if (this.auditService) {
      await this.auditService.log({
        organizationId,
        userId: currentUser?.id,
        userEmail: currentUser?.email,
        action: existing ? 'IOC_UPDATE' : 'IOC_CREATE',
        entityType: 'IOC',
        entityId: iocRecord.id,
        details: { type: iocRecord.type, value: iocRecord.value, source: iocRecord.source },
      });
    }

    const shared = this.mapToSharedIoc(iocRecord);
    if (this.eventsGateway) {
      this.eventsGateway.broadcastToOrg(organizationId, 'ioc:created', shared);
    }

    return shared;
  }

  /**
   * Update an existing IOC
   */
  async update(
    id: string,
    dto: UpdateIocDto,
    organizationId: string,
    currentUser?: AuthenticatedUser,
  ): Promise<SharedIOC> {
    await this.findById(id, organizationId);

    if (dto.type && dto.value && !this.validateIocFormat(dto.type as IOCType, dto.value)) {
      throw new BadRequestException(`Invalid ${dto.type} indicator format: "${dto.value}".`);
    }

    const updated = await this.prisma.indicatorOfCompromise.update({
      where: { id },
      data: {
        ...(dto.value && { value: dto.value.trim() }),
        ...(dto.type && { type: dto.type }),
        ...(dto.severity && { severity: dto.severity }),
        ...(dto.confidence !== undefined && { confidence: dto.confidence }),
        ...(dto.threatScore !== undefined && { threatScore: dto.threatScore }),
        ...(dto.source && { source: dto.source }),
        ...(dto.description !== undefined && { description: dto.description }),
        ...(dto.tags && { tags: dto.tags }),
        ...(dto.mitreTactics && { mitreTactics: dto.mitreTactics }),
        ...(dto.mitreTechniques && { mitreTechniques: dto.mitreTechniques }),
        ...(dto.isActive !== undefined && { isActive: dto.isActive }),
        lastSeen: new Date(),
      },
    });

    if (this.auditService) {
      await this.auditService.log({
        organizationId,
        userId: currentUser?.id,
        userEmail: currentUser?.email,
        action: 'IOC_UPDATE',
        entityType: 'IOC',
        entityId: id,
        details: { updates: dto },
      });
    }

    const shared = this.mapToSharedIoc(updated);
    if (this.eventsGateway) {
      this.eventsGateway.broadcastToOrg(organizationId, 'ioc:updated', shared);
    }

    return shared;
  }

  /**
   * Delete an IOC
   */
  async delete(
    id: string,
    organizationId: string,
    currentUser?: AuthenticatedUser,
  ): Promise<{ success: boolean; id: string }> {
    await this.findById(id, organizationId);

    await this.prisma.indicatorOfCompromise.delete({
      where: { id },
    });

    if (this.auditService) {
      await this.auditService.log({
        organizationId,
        userId: currentUser?.id,
        userEmail: currentUser?.email,
        action: 'IOC_DELETE',
        entityType: 'IOC',
        entityId: id,
      });
    }

    if (this.eventsGateway) {
      this.eventsGateway.broadcastToOrg(organizationId, 'ioc:deleted', { id });
    }

    return { success: true, id };
  }
}
