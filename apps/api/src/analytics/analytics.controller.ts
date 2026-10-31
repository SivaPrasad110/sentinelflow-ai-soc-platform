import {
  Controller,
  Get,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { AnalyticsService } from './analytics.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { CurrentOrg } from '../auth/decorators/current-user.decorator';
import { Role } from '@prisma/client';
import { SOCMetricsResponse } from '@sentinelflow/shared';

@ApiTags('SOC Analytics')
@Controller('analytics')
@UseGuards(JwtAuthGuard, RolesGuard)
@ApiBearerAuth()
@UsePipes(new ValidationPipe({ transform: true, whitelist: true }))
export class AnalyticsController {
  constructor(private readonly analyticsService: AnalyticsService) {}

  @Get('soc-metrics')
  @Roles(Role.VIEWER, Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'Retrieve advanced SOC monitoring metrics, MTTA, MTTR, and alert trends for the authorized organization' })
  @ApiResponse({ status: 200, description: 'Returns tenant-isolated SOC telemetry and metrics' })
  @ApiResponse({ status: 401, description: 'Authentication required' })
  @ApiResponse({ status: 403, description: 'Cross-tenant access forbidden' })
  async getSocMetrics(@CurrentOrg() orgId: string): Promise<SOCMetricsResponse> {
    return this.analyticsService.getSocMetrics(orgId);
  }
}
