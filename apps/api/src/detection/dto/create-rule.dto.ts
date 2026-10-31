import {
  IsNotEmpty,
  IsString,
  IsEnum,
  IsOptional,
  IsArray,
  IsBoolean,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Severity } from '@prisma/client';

export class RuleCriterionDto {
  @ApiProperty({ description: 'Target field on alert or IOC', example: 'title' })
  @IsString()
  @IsNotEmpty()
  field: string;

  @ApiProperty({
    description: 'Operator to evaluate against',
    enum: ['EQUALS', 'CONTAINS', 'STARTS_WITH', 'REGEX', 'IN', 'GREATER_THAN'],
    example: 'CONTAINS',
  })
  @IsString()
  @IsNotEmpty()
  operator: 'EQUALS' | 'CONTAINS' | 'STARTS_WITH' | 'REGEX' | 'IN' | 'GREATER_THAN';

  @ApiProperty({ description: 'Value to compare with', example: 'PowerShell' })
  @IsNotEmpty()
  value: any;
}

export class CreateRuleDto {
  @ApiProperty({ description: 'Name of the detection rule', example: 'Suspicious PowerShell Execution Rule' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({ description: 'Description and intent of the detection' })
  @IsString()
  @IsNotEmpty()
  description: string;

  @ApiPropertyOptional({ enum: Severity, default: Severity.HIGH })
  @IsEnum(Severity)
  @IsOptional()
  severity?: Severity;

  @ApiPropertyOptional({
    description: 'Rule evaluation type',
    enum: ['IOC_MATCH', 'PATTERN', 'THRESHOLD'],
    default: 'PATTERN',
  })
  @IsString()
  @IsOptional()
  ruleType?: 'IOC_MATCH' | 'PATTERN' | 'THRESHOLD';

  @ApiProperty({ type: [RuleCriterionDto], description: 'Criteria matching conditions' })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => RuleCriterionDto)
  criteria: RuleCriterionDto[];

  @ApiPropertyOptional({ description: 'MITRE ATT&CK Tactic name', example: 'Execution' })
  @IsString()
  @IsOptional()
  mitreTactic?: string;

  @ApiPropertyOptional({ description: 'MITRE ATT&CK Technique name', example: 'PowerShell' })
  @IsString()
  @IsOptional()
  mitreTechnique?: string;

  @ApiPropertyOptional({ description: 'MITRE ATT&CK Technique ID', example: 'T1059.001' })
  @IsString()
  @IsOptional()
  mitreTechniqueId?: string;

  @ApiPropertyOptional({ default: true })
  @IsBoolean()
  @IsOptional()
  enabled?: boolean;
}
