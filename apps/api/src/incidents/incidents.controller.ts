import { Controller, Get, Post, Body, Param } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam } from '@nestjs/swagger';
import { IncidentsService } from './incidents.service';
import { Incident } from '@sentinelflow/shared';

@ApiTags('Incidents')
@Controller('incidents')
export class IncidentsController {
  constructor(private readonly incidentsService: IncidentsService) {}

  @Get()
  @ApiOperation({ summary: 'List all active security incidents' })
  @ApiResponse({ status: 200, description: 'Returns an array of security incidents' })
  findAll(): Incident[] {
    return this.incidentsService.findAll();
  }

  @Get(':id')
  @ApiOperation({ summary: 'Retrieve incident details by ID' })
  @ApiParam({ name: 'id', description: 'Incident ID (e.g. INC-2026-001)' })
  @ApiResponse({ status: 200, description: 'Returns details of specified incident' })
  @ApiResponse({ status: 404, description: 'Incident not found' })
  findById(@Param('id') id: string): Incident {
    return this.incidentsService.findById(id);
  }

  @Post()
  @ApiOperation({ summary: 'Create or ingest a new security incident' })
  @ApiResponse({ status: 201, description: 'Incident successfully created' })
  create(@Body() payload: Partial<Incident>): Incident {
    return this.incidentsService.create(payload);
  }
}
