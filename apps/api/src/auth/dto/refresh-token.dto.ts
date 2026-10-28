import { IsNotEmpty, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RefreshTokenDto {
  @ApiProperty({ example: '7f9a12c8b0e14d...' })
  @IsString()
  @IsNotEmpty()
  refreshToken: string;
}
