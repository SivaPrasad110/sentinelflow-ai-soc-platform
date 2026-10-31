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
} from '@nestjs/swagger';
import { IocService } from './ioc.service';
import { CreateIocDto } from './dto/create-ioc.dto';
import { UpdateIocDto } from './dto/update-ioc.dto';
import { QueryIocDto } from './dto/query-ioc.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { Role } from '@prisma/client';
import { CurrentOrg, CurrentUser, AuthenticatedUser } from '../auth/decorators/current-user.decorator';
import { IndicatorOfCompromise } from '@sentinelflow/shared';

@ApiTags('Threat Intelligence - IOCs')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('iocs')
export class IocController {
  constructor(private readonly iocService: IocService) {}

  @Get()
  @Roles(Role.VIEWER, Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'Search and query Indicators of Compromise for authorized organization' })
  @ApiResponse({ status: 200, description: 'List of matching indicators' })
  async findAll(
    @CurrentOrg() orgId: string,
    @Query() queryDto: QueryIocDto,
  ): Promise<IndicatorOfCompromise[]> {
    return this.iocService.findAll(orgId, queryDto);
  }

  @Get(':id')
  @Roles(Role.VIEWER, Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'Get indicator of compromise by ID' })
  @ApiParam({ name: 'id', description: 'IOC ID' })
  @ApiResponse({ status: 200, description: 'Indicator details' })
  @ApiResponse({ status: 404, description: 'Indicator not found' })
  async findById(
    @Param('id') id: string,
    @CurrentOrg() orgId: string,
  ): Promise<IndicatorOfCompromise> {
    return this.iocService.findById(id, orgId);
  }

  @Post()
  @Roles(Role.ANALYST, Role.ADMIN)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create or ingest a new Indicator of Compromise (Analyst or Admin)' })
  @ApiResponse({ status: 201, description: 'IOC created or updated' })
  @ApiResponse({ status: 400, description: 'Invalid indicator format' })
  async create(
    @Body() dto: CreateIocDto,
    @CurrentOrg() orgId: string,
    @CurrentUser() user: AuthenticatedUser,
  ): Promise<IndicatorOfCompromise> {
    return this.iocService.create(dto, orgId, user);
  }

  @Patch(':id')
  @Roles(Role.ANALYST, Role.ADMIN)
  @ApiOperation({ summary: 'Update an existing Indicator of Compromise' })
  @ApiParam({ name: 'id', description: 'IOC ID' })
  @ApiResponse({ status: 200, description: 'Indicator updated successfully' })
  @ApiResponse({ status: 404, description: 'Indicator not found' })
  async update(
    @Param('id') id: string,
    @Body() dto: UpdateIocDto,
    @CurrentOrg() orgId: string,
    @CurrentUser() user: AuthenticatedUser,
  ): Promise<IndicatorOfCompromise> {
    return this.iocService.update(id, dto, orgId, user);
  }

  @Delete(':id')
  @Roles(Role.ADMIN)
  @ApiOperation({ summary: 'Delete an Indicator of Compromise (Admin Only)' })
  @ApiParam({ name: 'id', description: 'IOC ID' })
  @ApiResponse({ status: 200, description: 'Indicator deleted' })
  @ApiResponse({ status: 403, description: 'Forbidden: Admin only' })
  @ApiResponse({ status: 404, description: 'Indicator not found' })
  async delete(
    @Param('id') id: string,
    @CurrentOrg() orgId: string,
    @CurrentUser() user: AuthenticatedUser,
  ): Promise<{ success: boolean; id: string }> {
    return this.iocService.delete(id, orgId, user);
  }
}
