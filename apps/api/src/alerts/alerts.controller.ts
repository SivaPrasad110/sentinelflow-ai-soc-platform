import { Controller, Get, Post, Body } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { AlertsService } from './alerts.service';
import { SecurityAlert } from '@sentinelflow/shared';

@ApiTags('Alerts')
@Controller('alerts')
export class AlertsController {
  constructor(private readonly alertsService: AlertsService) {}

  @Get()
  @ApiOperation({ summary: 'List recent ingested security alerts' })
  @ApiResponse({ status: 200, description: 'Returns an array of security alerts' })
  findAll(): SecurityAlert[] {
    return this.alertsService.findAll();
  }

  @Post()
  @ApiOperation({ summary: 'Ingest raw security alert from EDR/SIEM/WAF sources' })
  @ApiResponse({ status: 201, description: 'Alert successfully ingested' })
  ingest(@Body() alert: Partial<SecurityAlert>): SecurityAlert {
    return this.alertsService.ingest(alert);
  }
}
