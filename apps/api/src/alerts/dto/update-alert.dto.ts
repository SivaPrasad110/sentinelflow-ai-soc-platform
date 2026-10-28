import { IsString, IsEnum, IsOptional } from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';
import { Severity } from '@prisma/client';

export class UpdateAlertDto {
  @ApiPropertyOptional({ example: 'Updated alert title' })
  @IsOptional()
  @IsString()
  title?: string;

  @ApiPropertyOptional({ example: 'Updated alert description' })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional({ enum: Severity })
  @IsOptional()
  @IsEnum(Severity)
  severity?: Severity;

  @ApiPropertyOptional({ example: 'INC-2026-001' })
  @IsOptional()
  @IsString()
  incidentId?: string;
}
