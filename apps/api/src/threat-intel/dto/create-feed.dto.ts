import { IsNotEmpty, IsString, IsUrl, IsOptional, IsBoolean, IsIn } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateFeedDto {
  @ApiProperty({ description: 'Display name of threat feed', example: 'URLhaus Recent Feeds' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({ description: 'Endpoint URL to fetch defensive indicators from' })
  @IsUrl()
  @IsNotEmpty()
  feedUrl: string;

  @ApiPropertyOptional({ description: 'Feed source identifier', default: 'CUSTOM' })
  @IsString()
  @IsOptional()
  @IsIn(['URLHAUS', 'THREATFOX', 'MALWARE_BAZAAR', 'BLOCKLIST', 'CUSTOM'])
  feedType?: string;

  @ApiPropertyOptional({ description: 'Data format', default: 'JSON' })
  @IsString()
  @IsOptional()
  @IsIn(['JSON', 'CSV', 'TEXT'])
  format?: string;

  @ApiPropertyOptional({ description: 'Whether feed is active', default: true })
  @IsBoolean()
  @IsOptional()
  enabled?: boolean;
}
