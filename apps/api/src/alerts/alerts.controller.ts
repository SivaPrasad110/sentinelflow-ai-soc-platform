import {
  Controller,
  Get,
  Post,
  Patch,
  Body,
  Param,
  Headers,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam, ApiHeader } from '@nestjs/swagger';
import { AlertsService } from './alerts.service';
import { IngestAlertDto } from './dto/ingest-alert.dto';
import { UpdateAlertDto } from './dto/update-alert.dto';
import { SecurityAlert } from '@sentinelflow/shared';

@ApiTags('Alerts')
@Controller('alerts')
@UsePipes(new ValidationPipe({ transform: true, whitelist: true }))
export class AlertsController {
  constructor(private readonly alertsService: AlertsService) {}

  @Get()
  @ApiOperation({ summary: 'List recent ingested security alerts' })
  @ApiHeader({ name: 'x-tenant-id', required: false, description: 'Tenant identifier' })
  @ApiResponse({ status: 200, description: 'Returns an array of security alerts' })
  async findAll(@Headers('x-tenant-id') tenantId?: string): Promise<SecurityAlert[]> {
    return this.alertsService.findAll(tenantId);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Retrieve security alert by ID' })
  @ApiParam({ name: 'id', description: 'Alert ID' })
  @ApiHeader({ name: 'x-tenant-id', required: false, description: 'Tenant identifier' })
  @ApiResponse({ status: 200, description: 'Returns details of specified alert' })
  @ApiResponse({ status: 404, description: 'Alert not found' })
  async findById(
    @Param('id') id: string,
    @Headers('x-tenant-id') tenantId?: string,
  ): Promise<SecurityAlert> {
    return this.alertsService.findById(id, tenantId);
  }

  @Post()
  @ApiOperation({ summary: 'Ingest raw security alert from EDR/SIEM/WAF sources' })
  @ApiHeader({ name: 'x-tenant-id', required: false, description: 'Tenant identifier' })
  @ApiResponse({ status: 201, description: 'Alert successfully ingested and persisted' })
  async ingest(
    @Body() dto: IngestAlertDto,
    @Headers('x-tenant-id') tenantId?: string,
  ): Promise<SecurityAlert> {
    return this.alertsService.ingest(dto, tenantId);
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update an ingested security alert' })
  @ApiParam({ name: 'id', description: 'Alert ID' })
  @ApiHeader({ name: 'x-tenant-id', required: false, description: 'Tenant identifier' })
  @ApiResponse({ status: 200, description: 'Alert successfully updated' })
  @ApiResponse({ status: 404, description: 'Alert not found' })
  async update(
    @Param('id') id: string,
    @Body() dto: UpdateAlertDto,
    @Headers('x-tenant-id') tenantId?: string,
  ): Promise<SecurityAlert> {
    return this.alertsService.update(id, dto, tenantId);
  }
}
