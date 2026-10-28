import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Headers,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam, ApiHeader } from '@nestjs/swagger';
import { IncidentsService } from './incidents.service';
import { CreateIncidentDto } from './dto/create-incident.dto';
import { UpdateIncidentDto } from './dto/update-incident.dto';
import { Incident } from '@sentinelflow/shared';

@ApiTags('Incidents')
@Controller('incidents')
@UsePipes(new ValidationPipe({ transform: true, whitelist: true }))
export class IncidentsController {
  constructor(private readonly incidentsService: IncidentsService) {}

  @Get()
  @ApiOperation({ summary: 'List all active security incidents' })
  @ApiHeader({ name: 'x-tenant-id', required: false, description: 'Tenant identifier for multi-tenant isolation' })
  @ApiResponse({ status: 200, description: 'Returns an array of security incidents' })
  async findAll(@Headers('x-tenant-id') tenantId?: string): Promise<Incident[]> {
    return this.incidentsService.findAll(tenantId);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Retrieve incident details by ID' })
  @ApiParam({ name: 'id', description: 'Incident ID (e.g. INC-2026-001 or UUID)' })
  @ApiHeader({ name: 'x-tenant-id', required: false, description: 'Tenant identifier' })
  @ApiResponse({ status: 200, description: 'Returns details of specified incident' })
  @ApiResponse({ status: 404, description: 'Incident not found' })
  async findById(
    @Param('id') id: string,
    @Headers('x-tenant-id') tenantId?: string,
  ): Promise<Incident> {
    return this.incidentsService.findById(id, tenantId);
  }

  @Post()
  @ApiOperation({ summary: 'Create or ingest a new security incident' })
  @ApiHeader({ name: 'x-tenant-id', required: false, description: 'Tenant identifier' })
  @ApiResponse({ status: 201, description: 'Incident successfully created in persistent storage' })
  async create(
    @Body() dto: CreateIncidentDto,
    @Headers('x-tenant-id') tenantId?: string,
  ): Promise<Incident> {
    return this.incidentsService.create(dto, tenantId);
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update an existing security incident' })
  @ApiParam({ name: 'id', description: 'Incident ID to update' })
  @ApiHeader({ name: 'x-tenant-id', required: false, description: 'Tenant identifier' })
  @ApiResponse({ status: 200, description: 'Incident successfully updated' })
  @ApiResponse({ status: 404, description: 'Incident not found' })
  async update(
    @Param('id') id: string,
    @Body() dto: UpdateIncidentDto,
    @Headers('x-tenant-id') tenantId?: string,
  ): Promise<Incident> {
    return this.incidentsService.update(id, dto, tenantId);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Delete a security incident' })
  @ApiParam({ name: 'id', description: 'Incident ID to delete' })
  @ApiHeader({ name: 'x-tenant-id', required: false, description: 'Tenant identifier' })
  @ApiResponse({ status: 200, description: 'Incident successfully deleted' })
  @ApiResponse({ status: 404, description: 'Incident not found' })
  async delete(
    @Param('id') id: string,
    @Headers('x-tenant-id') tenantId?: string,
  ): Promise<{ success: boolean; id: string }> {
    return this.incidentsService.delete(id, tenantId);
  }
}
