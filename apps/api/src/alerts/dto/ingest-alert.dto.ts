import {
  IsString,
  IsNotEmpty,
  IsEnum,
  IsOptional,
  IsDateString,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Severity } from '@prisma/client';

export class IngestAlertDto {
  @ApiProperty({ example: 'PowerShell EncodedCommand Execution' })
  @IsString()
  @IsNotEmpty()
  title: string;

  @ApiProperty({ example: 'Host WS-FIN-04 executed powershell.exe -enc with elevated permissions.' })
  @IsString()
  @IsNotEmpty()
  description: string;

  @ApiPropertyOptional({ enum: Severity, default: Severity.MEDIUM })
  @IsOptional()
  @IsEnum(Severity)
  severity?: Severity;

  @ApiProperty({ example: 'CrowdStrike Falcon EDR' })
  @IsString()
  @IsNotEmpty()
  source: string;

  @ApiPropertyOptional({ example: 'default-tenant' })
  @IsOptional()
  @IsString()
  tenantId?: string;

  @ApiPropertyOptional({ example: 'INC-2026-001' })
  @IsOptional()
  @IsString()
  incidentId?: string;

  @ApiPropertyOptional()
  @IsOptional()
  rawPayload?: Record<string, unknown>;

  @ApiPropertyOptional({ example: '2026-10-28T10:00:00.000Z' })
  @IsOptional()
  @IsDateString()
  detectedAt?: string;
}
