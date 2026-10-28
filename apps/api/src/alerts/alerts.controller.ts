import {
  Controller,
  Get,
  Post,
  Patch,
  Body,
  Param,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam, ApiBearerAuth } from '@nestjs/swagger';
import { AlertsService } from './alerts.service';
import { IngestAlertDto } from './dto/ingest-alert.dto';
import { UpdateAlertDto } from './dto/update-alert.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { CurrentOrg } from '../auth/decorators/current-user.decorator';
import { Role } from '@prisma/client';
import { SecurityAlert } from '@sentinelflow/shared';

@ApiTags('Alerts')
@Controller('alerts')
@UseGuards(JwtAuthGuard, RolesGuard)
@ApiBearerAuth()
@UsePipes(new ValidationPipe({ transform: true, whitelist: true }))
export class AlertsController {
  constructor(private readonly alertsService: AlertsService) {}

  @Get()
  @Roles(Role.VIEWER, Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'List recent ingested security alerts within the authorized organization' })
  @ApiResponse({ status: 200, description: 'Returns an array of scoped security alerts' })
  async findAll(@CurrentOrg() orgId: string): Promise<SecurityAlert[]> {
    return this.alertsService.findAll(orgId);
  }

  @Get(':id')
  @Roles(Role.VIEWER, Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'Retrieve security alert by ID within the authorized organization' })
  @ApiParam({ name: 'id', description: 'Alert ID' })
  @ApiResponse({ status: 200, description: 'Returns details of specified alert' })
  @ApiResponse({ status: 404, description: 'Alert not found in organization' })
  async findById(
    @Param('id') id: string,
    @CurrentOrg() orgId: string,
  ): Promise<SecurityAlert> {
    return this.alertsService.findById(id, orgId);
  }

  @Post()
  @Roles(Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'Ingest raw security alert from EDR/SIEM/WAF sources into authorized organization' })
  @ApiResponse({ status: 201, description: 'Alert successfully ingested and persisted' })
  @ApiResponse({ status: 403, description: 'Insufficient permissions (VIEWER cannot ingest alerts)' })
  async ingest(
    @Body() dto: IngestAlertDto,
    @CurrentOrg() orgId: string,
  ): Promise<SecurityAlert> {
    return this.alertsService.ingest(dto, orgId);
  }

  @Patch(':id')
  @Roles(Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'Update an ingested security alert' })
  @ApiParam({ name: 'id', description: 'Alert ID' })
  @ApiResponse({ status: 200, description: 'Alert successfully updated' })
  @ApiResponse({ status: 404, description: 'Alert not found' })
  async update(
    @Param('id') id: string,
    @Body() dto: UpdateAlertDto,
    @CurrentOrg() orgId: string,
  ): Promise<SecurityAlert> {
    return this.alertsService.update(id, dto, orgId);
  }
}
