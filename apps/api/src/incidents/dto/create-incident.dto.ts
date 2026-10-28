import {
  IsString,
  IsNotEmpty,
  IsEnum,
  IsOptional,
  IsArray,
  ValidateNested,
  IsNumber,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Severity, IncidentStatus, IOCType } from '@prisma/client';

export class CreateIOCDto {
  @ApiProperty({ enum: IOCType, example: 'IP' })
  @IsEnum(IOCType)
  type: IOCType;

  @ApiProperty({ example: '198.51.100.42' })
  @IsString()
  @IsNotEmpty()
  value: string;

  @ApiPropertyOptional({ example: 85 })
  @IsOptional()
  @IsNumber()
  threatScore?: number;
}

export class CreateIncidentDto {
  @ApiProperty({ example: 'Suspicious PowerShell Execution & EDR Evasion' })
  @IsString()
  @IsNotEmpty()
  title: string;

  @ApiProperty({ example: 'Endpoint telemetry flagged obfuscated PowerShell execution.' })
  @IsString()
  @IsNotEmpty()
  description: string;

  @ApiPropertyOptional({ enum: Severity, default: Severity.MEDIUM })
  @IsOptional()
  @IsEnum(Severity)
  severity?: Severity;

  @ApiPropertyOptional({ enum: IncidentStatus, default: IncidentStatus.NEW })
  @IsOptional()
  @IsEnum(IncidentStatus)
  status?: IncidentStatus;

  @ApiPropertyOptional({ example: 'default-tenant' })
  @IsOptional()
  @IsString()
  tenantId?: string;

  @ApiPropertyOptional({ example: 'USR-SOC-001' })
  @IsOptional()
  @IsString()
  assignedToId?: string;

  @ApiPropertyOptional({ type: [String], example: ['ALT-9821'] })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  sourceAlertIds?: string[];

  @ApiPropertyOptional({ type: [String], example: ['Isolate affected host'] })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  mitigationSteps?: string[];

  @ApiPropertyOptional({ type: [CreateIOCDto] })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreateIOCDto)
  iocs?: CreateIOCDto[];

  @ApiPropertyOptional({ example: { summary: 'Potential credential access', confidenceScore: 0.91 } })
  @IsOptional()
  aiAnalysis?: Record<string, unknown>;
}
