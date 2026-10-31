import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiParam,
} from '@nestjs/swagger';
import { ThreatIntelService } from './threat-intel.service';
import { CreateFeedDto } from './dto/create-feed.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { Role } from '@prisma/client';
import { CurrentOrg, CurrentUser, AuthenticatedUser } from '../auth/decorators/current-user.decorator';
import {
  ThreatFeed,
  ThreatFeedSyncResult,
  ThreatIntelStatsResponse,
} from '@sentinelflow/shared';

@ApiTags('Threat Intelligence - Feeds')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('threat-intel')
export class ThreatIntelController {
  constructor(private readonly threatIntelService: ThreatIntelService) {}

  @Get('feeds')
  @Roles(Role.VIEWER, Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'List all threat intelligence feeds' })
  @ApiResponse({ status: 200, description: 'List of configured threat feeds' })
  async getFeeds(@CurrentOrg() orgId: string): Promise<ThreatFeed[]> {
    return this.threatIntelService.getFeeds(orgId);
  }

  @Post('feeds')
  @Roles(Role.ADMIN)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create a new threat intelligence feed (Admin Only)' })
  @ApiResponse({ status: 201, description: 'Threat feed created' })
  async createFeed(
    @Body() dto: CreateFeedDto,
    @CurrentOrg() orgId: string,
    @CurrentUser() user: AuthenticatedUser,
  ): Promise<ThreatFeed> {
    return this.threatIntelService.createFeed(dto, orgId, user);
  }

  @Post('feeds/:id/sync')
  @Roles(Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'Trigger synchronization of a threat intelligence feed' })
  @ApiParam({ name: 'id', description: 'Threat Feed ID' })
  @ApiResponse({ status: 200, description: 'Feed synchronization completed' })
  async syncFeed(
    @Param('id') feedId: string,
    @CurrentOrg() orgId: string,
    @CurrentUser() user: AuthenticatedUser,
  ): Promise<ThreatFeedSyncResult> {
    return this.threatIntelService.syncFeed(feedId, orgId, user);
  }

  @Get('stats')
  @Roles(Role.VIEWER, Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'Retrieve high-level threat intelligence metrics and MITRE coverage' })
  @ApiResponse({ status: 200, description: 'Threat intelligence statistics' })
  async getStats(@CurrentOrg() orgId: string): Promise<ThreatIntelStatsResponse> {
    return this.threatIntelService.getStats(orgId);
  }
}
