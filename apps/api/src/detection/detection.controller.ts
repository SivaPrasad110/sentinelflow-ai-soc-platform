import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Query,
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
  ApiQuery,
} from '@nestjs/swagger';
import { DetectionService } from './detection.service';
import { MitreAttackService } from './mitre/mitre-attack.service';
import { CreateRuleDto } from './dto/create-rule.dto';
import { UpdateRuleDto } from './dto/update-rule.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { Role } from '@prisma/client';
import { CurrentOrg, CurrentUser, AuthenticatedUser } from '../auth/decorators/current-user.decorator';
import {
  DetectionRule,
  SecurityFinding,
  Incident,
  MitreTechnique,
} from '@sentinelflow/shared';

@ApiTags('Detection Engine & Findings')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('detection')
export class DetectionController {
  constructor(
    private readonly detectionService: DetectionService,
    private readonly mitreService: MitreAttackService,
  ) {}

  // ==========================================
  // Rules Endpoints
  // ==========================================

  @Get('rules')
  @Roles(Role.VIEWER, Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'List all detection rules for organization' })
  @ApiResponse({ status: 200, description: 'List of detection rules' })
  async getRules(@CurrentOrg() orgId: string): Promise<DetectionRule[]> {
    return this.detectionService.findAllRules(orgId);
  }

  @Get('rules/:id')
  @Roles(Role.VIEWER, Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'Get detection rule by ID' })
  @ApiParam({ name: 'id', description: 'Rule ID' })
  @ApiResponse({ status: 200, description: 'Rule details' })
  @ApiResponse({ status: 404, description: 'Rule not found' })
  async getRuleById(
    @Param('id') id: string,
    @CurrentOrg() orgId: string,
  ): Promise<DetectionRule> {
    return this.detectionService.findRuleById(id, orgId);
  }

  @Post('rules')
  @Roles(Role.ANALYST, Role.ADMIN)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create a new detection rule' })
  @ApiResponse({ status: 201, description: 'Rule created' })
  @ApiResponse({ status: 400, description: 'Invalid rule criteria or MITRE mapping' })
  async createRule(
    @CurrentOrg() orgId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Body() dto: CreateRuleDto,
  ): Promise<DetectionRule> {
    return this.detectionService.createRule(dto, orgId, user);
  }

  @Patch('rules/:id')
  @Roles(Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'Update an existing detection rule' })
  @ApiParam({ name: 'id', description: 'Rule ID' })
  @ApiResponse({ status: 200, description: 'Rule updated' })
  @ApiResponse({ status: 404, description: 'Rule not found' })
  async updateRule(
    @Param('id') id: string,
    @CurrentOrg() orgId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Body() dto: UpdateRuleDto,
  ): Promise<DetectionRule> {
    return this.detectionService.updateRule(id, dto, orgId, user);
  }

  @Patch('rules/:id/toggle')
  @Roles(Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'Toggle rule active state' })
  @ApiParam({ name: 'id', description: 'Rule ID' })
  @ApiResponse({ status: 200, description: 'Rule updated' })
  async toggleRule(
    @Param('id') id: string,
    @CurrentOrg() orgId: string,
    @Body() body?: { enabled?: boolean },
  ): Promise<DetectionRule> {
    return this.detectionService.toggleRule(id, orgId, body?.enabled);
  }

  @Delete('rules/:id')
  @Roles(Role.ADMIN)
  @ApiOperation({ summary: 'Delete a detection rule (Admin only)' })
  @ApiParam({ name: 'id', description: 'Rule ID' })
  @ApiResponse({ status: 200, description: 'Rule deleted' })
  async deleteRule(
    @Param('id') id: string,
    @CurrentOrg() orgId: string,
    @CurrentUser() user: AuthenticatedUser,
  ): Promise<{ success: boolean }> {
    return this.detectionService.deleteRule(id, orgId, user);
  }

  // ==========================================
  // MITRE ATT&CK Matrix Endpoints
  // ==========================================

  @Get('mitre/tactics')
  @Roles(Role.VIEWER, Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'Get list of supported Enterprise ATT&CK tactics' })
  async getMitreTactics() {
    return this.mitreService.getTactics();
  }

  @Get('mitre/techniques')
  @Roles(Role.VIEWER, Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'Get list of official Enterprise ATT&CK techniques' })
  async getMitreTechniques(): Promise<MitreTechnique[]> {
    return this.mitreService.getAllTechniques();
  }

  @Get('mitre/matrix')
  @Roles(Role.VIEWER, Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'Get full Enterprise ATT&CK matrix structured by tactics' })
  async getMitreMatrix() {
    const tactics = this.mitreService.getTactics();
    const matrix = tactics.map((tactic) => ({
      ...tactic,
      techniques: this.mitreService.getTechniquesByTactic(tactic.id),
    }));
    return matrix;
  }

  // ==========================================
  // Findings Endpoints
  // ==========================================

  @Get('findings')
  @Roles(Role.VIEWER, Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'List security findings for organization' })
  @ApiQuery({ name: 'status', required: false, enum: ['NEW', 'ANALYZED', 'PROMOTED', 'DISMISSED'] })
  @ApiQuery({ name: 'severity', required: false, enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] })
  @ApiResponse({ status: 200, description: 'List of security findings' })
  async getFindings(
    @CurrentOrg() orgId: string,
    @Query('status') status?: string,
    @Query('severity') severity?: string,
  ): Promise<SecurityFinding[]> {
    return this.detectionService.findAllFindings(orgId, { status, severity });
  }

  @Get('findings/:id')
  @Roles(Role.VIEWER, Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'Get security finding by ID' })
  @ApiParam({ name: 'id', description: 'Finding ID' })
  @ApiResponse({ status: 200, description: 'Finding details' })
  @ApiResponse({ status: 404, description: 'Finding not found' })
  async getFindingById(
    @Param('id') id: string,
    @CurrentOrg() orgId: string,
  ): Promise<SecurityFinding> {
    return this.detectionService.findFindingById(id, orgId);
  }

  @Post('findings/:id/promote')
  @Roles(Role.ANALYST, Role.ADMIN)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Promote/Escalate a security finding to an active Incident' })
  @ApiParam({ name: 'id', description: 'Finding ID' })
  @ApiResponse({ status: 200, description: 'Incident created from finding' })
  async promoteFinding(
    @Param('id') id: string,
    @CurrentOrg() orgId: string,
    @CurrentUser() user: AuthenticatedUser,
  ): Promise<Incident> {
    return this.detectionService.promoteToIncident(id, orgId, user);
  }

  @Post('findings/:id/dismiss')
  @Roles(Role.ANALYST, Role.ADMIN)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Dismiss a security finding' })
  @ApiParam({ name: 'id', description: 'Finding ID' })
  @ApiResponse({ status: 200, description: 'Finding dismissed' })
  async dismissFinding(
    @Param('id') id: string,
    @CurrentOrg() orgId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Body() body?: { reason?: string },
  ): Promise<SecurityFinding> {
    return this.detectionService.dismissFinding(id, orgId, body?.reason, user);
  }
}
