import {
  Controller,
  Get,
  Query,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiQuery } from '@nestjs/swagger';
import { AuditService } from './audit.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { CurrentOrg } from '../auth/decorators/current-user.decorator';
import { Role } from '@prisma/client';
import { AuditLogRecord } from '@sentinelflow/shared';

@ApiTags('Audit Logs')
@Controller('audit-logs')
@UseGuards(JwtAuthGuard, RolesGuard)
@ApiBearerAuth()
@UsePipes(new ValidationPipe({ transform: true, whitelist: true }))
export class AuditController {
  constructor(private readonly auditService: AuditService) {}

  @Get()
  @Roles(Role.ADMIN, Role.ANALYST)
  @ApiOperation({ summary: 'Retrieve immutable security audit trail for the authorized organization' })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  @ApiQuery({ name: 'action', required: false, type: String })
  @ApiResponse({ status: 200, description: 'Returns array of audit records' })
  @ApiResponse({ status: 403, description: 'Forbidden: VIEWER cannot view audit logs' })
  async getAuditLogs(
    @CurrentOrg() orgId: string,
    @Query('limit') limit?: number,
    @Query('action') action?: string,
  ): Promise<AuditLogRecord[]> {
    return this.auditService.findByOrganization(orgId, limit ? Number(limit) : 50, action);
  }
}
