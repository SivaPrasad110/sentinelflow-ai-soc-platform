import { IsOptional, IsString, IsEnum, IsBoolean } from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';
import { IOCType, Severity } from '@prisma/client';
import { Type } from 'class-transformer';

export class QueryIocDto {
  @ApiPropertyOptional({ description: 'Search term for IOC value or description' })
  @IsString()
  @IsOptional()
  query?: string;

  @ApiPropertyOptional({ enum: IOCType })
  @IsEnum(IOCType)
  @IsOptional()
  type?: IOCType;

  @ApiPropertyOptional({ enum: Severity })
  @IsEnum(Severity)
  @IsOptional()
  severity?: Severity;

  @ApiPropertyOptional({ description: 'Source attribution filter' })
  @IsString()
  @IsOptional()
  source?: string;

  @ApiPropertyOptional({ description: 'Filter by active status' })
  @IsOptional()
  @Type(() => Boolean)
  @IsBoolean()
  isActive?: boolean;

  @ApiPropertyOptional({ description: 'Maximum results to return', default: 50 })
  @IsOptional()
  @Type(() => Number)
  limit?: number;
}
