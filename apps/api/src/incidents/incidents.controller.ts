import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam, ApiBearerAuth } from '@nestjs/swagger';
import { IncidentsService } from './incidents.service';
import { N8nIntegrationService } from '../n8n/n8n.service';
import { CreateIncidentDto } from './dto/create-incident.dto';
import { UpdateIncidentDto } from './dto/update-incident.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { CurrentOrg, CurrentUser, AuthenticatedUser } from '../auth/decorators/current-user.decorator';
import { Role } from '@prisma/client';
import { Incident, IncidentAnalysisRecord } from '@sentinelflow/shared';

@ApiTags('Incidents')
@Controller('incidents')
@UseGuards(JwtAuthGuard, RolesGuard)
@ApiBearerAuth()
@UsePipes(new ValidationPipe({ transform: true, whitelist: true }))
export class IncidentsController {
  constructor(
    private readonly incidentsService: IncidentsService,
    private readonly n8nService: N8nIntegrationService,
  ) {}

  @Get()
  @Roles(Role.VIEWER, Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'List all active security incidents in the authorized organization' })
  @ApiResponse({ status: 200, description: 'Returns an array of scoped security incidents' })
  @ApiResponse({ status: 401, description: 'Authentication required' })
  @ApiResponse({ status: 403, description: 'Insufficient permissions or cross-tenant access denied' })
  async findAll(@CurrentOrg() orgId: string): Promise<Incident[]> {
    return this.incidentsService.findAll(orgId);
  }

  @Get(':id')
  @Roles(Role.VIEWER, Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'Retrieve incident details by ID within the authorized organization' })
  @ApiParam({ name: 'id', description: 'Incident ID' })
  @ApiResponse({ status: 200, description: 'Returns details of specified incident' })
  @ApiResponse({ status: 404, description: 'Incident not found in authorized organization' })
  async findById(
    @Param('id') id: string,
    @CurrentOrg() orgId: string,
  ): Promise<Incident> {
    return this.incidentsService.findById(id, orgId);
  }

  @Post()
  @Roles(Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'Create a new security incident (Requires ANALYST or ADMIN role)' })
  @ApiResponse({ status: 201, description: 'Incident successfully created in organization' })
  @ApiResponse({ status: 403, description: 'Insufficient role (e.g. VIEWER cannot create incidents)' })
  async create(
    @Body() dto: CreateIncidentDto,
    @CurrentOrg() orgId: string,
    @CurrentUser() user: AuthenticatedUser,
  ): Promise<Incident> {
    return this.incidentsService.create(dto, orgId, user.id);
  }

  @Patch(':id')
  @Roles(Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'Update an existing security incident (Requires ANALYST or ADMIN role)' })
  @ApiParam({ name: 'id', description: 'Incident ID to update' })
  @ApiResponse({ status: 200, description: 'Incident successfully updated' })
  @ApiResponse({ status: 403, description: 'Insufficient role' })
  @ApiResponse({ status: 404, description: 'Incident not found' })
  async update(
    @Param('id') id: string,
    @Body() dto: UpdateIncidentDto,
    @CurrentOrg() orgId: string,
  ): Promise<Incident> {
    return this.incidentsService.update(id, dto, orgId);
  }

  @Delete(':id')
  @Roles(Role.ADMIN)
  @ApiOperation({ summary: 'Delete a security incident (Requires ADMIN role)' })
  @ApiParam({ name: 'id', description: 'Incident ID to delete' })
  @ApiResponse({ status: 200, description: 'Incident successfully deleted' })
  @ApiResponse({ status: 403, description: 'Forbidden: only ADMIN can delete incidents' })
  @ApiResponse({ status: 404, description: 'Incident not found' })
  async delete(
    @Param('id') id: string,
    @CurrentOrg() orgId: string,
  ): Promise<{ success: boolean; id: string }> {
    return this.incidentsService.delete(id, orgId);
  }

  @Post(':id/analyze')
  @Roles(Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'Trigger AI incident triage via n8n Cloud (Requires ANALYST or ADMIN role)' })
  @ApiParam({ name: 'id', description: 'Incident ID to analyze' })
  @ApiResponse({ status: 200, description: 'Triage successfully analyzed and persisted' })
  @ApiResponse({ status: 403, description: 'Forbidden: VIEWER cannot trigger AI triage' })
  @ApiResponse({ status: 404, description: 'Incident not found in authorized organization' })
  @ApiResponse({ status: 409, description: 'AI Triage analysis is already in progress for this incident' })
  @ApiResponse({ status: 502, description: 'Failed to communicate with n8n or received malformed response' })
  async analyze(
    @Param('id') id: string,
    @CurrentOrg() orgId: string,
    @CurrentUser() user: AuthenticatedUser,
  ): Promise<IncidentAnalysisRecord> {
    return this.n8nService.triggerTriage(id, orgId, user.id);
  }

  @Get(':id/analyses')
  @Roles(Role.VIEWER, Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'Retrieve AI triage analysis history for an incident' })
  @ApiParam({ name: 'id', description: 'Incident ID' })
  @ApiResponse({ status: 200, description: 'Returns an array of past analysis records' })
  @ApiResponse({ status: 404, description: 'Incident not found in authorized organization' })
  async getAnalyses(
    @Param('id') id: string,
    @CurrentOrg() orgId: string,
  ): Promise<IncidentAnalysisRecord[]> {
    return this.n8nService.getIncidentAnalyses(id, orgId);
  }
}
