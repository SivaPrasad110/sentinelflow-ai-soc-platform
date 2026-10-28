import { IsEmail, IsNotEmpty, IsString, MinLength, IsOptional } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class LoginDto {
  @ApiProperty({ example: 'sarah.chen@sentinelflow.local' })
  @IsEmail({}, { message: 'A valid email address is required.' })
  @IsNotEmpty()
  email: string;

  @ApiProperty({ example: 'AnalystPassword123!' })
  @IsString()
  @IsNotEmpty()
  @MinLength(8, { message: 'Password must be at least 8 characters long.' })
  password: string;

  @ApiPropertyOptional({ example: 'org-cyberdefense-001', description: 'Optional organization selection hint' })
  @IsOptional()
  @IsString()
  organizationIdHint?: string;
}
