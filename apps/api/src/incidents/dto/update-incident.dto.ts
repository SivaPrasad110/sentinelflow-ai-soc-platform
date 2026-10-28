import {
  IsString,
  IsEnum,
  IsOptional,
  IsArray,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiPropertyOptional } from '@nestjs/swagger';
import { Severity, IncidentStatus } from '@prisma/client';
import { CreateIOCDto } from './create-incident.dto';

export class UpdateIncidentDto {
  @ApiPropertyOptional({ example: 'Updated incident title' })
  @IsOptional()
  @IsString()
  title?: string;

  @ApiPropertyOptional({ example: 'Updated detailed description' })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional({ enum: Severity })
  @IsOptional()
  @IsEnum(Severity)
  severity?: Severity;

  @ApiPropertyOptional({ enum: IncidentStatus })
  @IsOptional()
  @IsEnum(IncidentStatus)
  status?: IncidentStatus;

  @ApiPropertyOptional({ example: 'USR-SOC-001' })
  @IsOptional()
  @IsString()
  assignedToId?: string;

  @ApiPropertyOptional({ type: [String] })
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

  @ApiPropertyOptional()
  @IsOptional()
  aiAnalysis?: Record<string, unknown>;
}
