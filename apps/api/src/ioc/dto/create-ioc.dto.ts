import { IsEnum, IsNotEmpty, IsOptional, IsString, IsNumber, Min, Max, IsArray, IsBoolean } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IOCType, Severity } from '@prisma/client';

export class CreateIocDto {
  @ApiProperty({ enum: IOCType, description: 'Type of indicator' })
  @IsEnum(IOCType)
  @IsNotEmpty()
  type: IOCType;

  @ApiProperty({ description: 'Indicator value (IP, domain, URL, hash, email)', example: '198.51.100.42' })
  @IsString()
  @IsNotEmpty()
  value: string;

  @ApiPropertyOptional({ enum: Severity, default: Severity.MEDIUM })
  @IsEnum(Severity)
  @IsOptional()
  severity?: Severity;

  @ApiPropertyOptional({ description: 'Confidence score (0.0 to 1.0)', example: 0.85 })
  @IsNumber()
  @Min(0)
  @Max(1)
  @IsOptional()
  confidence?: number;

  @ApiPropertyOptional({ description: 'Threat score (0 to 100)', example: 85 })
  @IsNumber()
  @Min(0)
  @Max(100)
  @IsOptional()
  threatScore?: number;

  @ApiPropertyOptional({ description: 'Source attribution', example: 'ThreatFox / Abuse.ch' })
  @IsString()
  @IsOptional()
  source?: string;

  @ApiPropertyOptional({ description: 'Indicator description or context' })
  @IsString()
  @IsOptional()
  description?: string;

  @ApiPropertyOptional({ description: 'Associated incident ID' })
  @IsString()
  @IsOptional()
  incidentId?: string;

  @ApiPropertyOptional({ type: [String], description: 'Tags for categorization' })
  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  tags?: string[];

  @ApiPropertyOptional({ type: [String], description: 'Associated MITRE ATT&CK tactics' })
  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  mitreTactics?: string[];

  @ApiPropertyOptional({ type: [String], description: 'Associated MITRE ATT&CK technique IDs' })
  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  mitreTechniques?: string[];

  @ApiPropertyOptional({ description: 'Active status', default: true })
  @IsBoolean()
  @IsOptional()
  isActive?: boolean;
}
