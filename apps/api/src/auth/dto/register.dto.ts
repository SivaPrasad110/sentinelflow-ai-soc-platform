import { IsEmail, IsNotEmpty, IsString, MinLength, Matches } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RegisterDto {
  @ApiProperty({ example: 'analyst@mysecops.io' })
  @IsEmail({}, { message: 'A valid corporate email address is required.' })
  @IsNotEmpty()
  email: string;

  @ApiProperty({ example: 'ProductionPassword!2026' })
  @IsString()
  @IsNotEmpty()
  @MinLength(10, { message: 'Password must be at least 10 characters long.' })
  @Matches(/(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9])/, {
    message: 'Password must contain uppercase, lowercase, number, and special character.',
  })
  password: string;

  @ApiProperty({ example: 'Jordan Vance' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({ example: 'Vance Threat Intel SOC' })
  @IsString()
  @IsNotEmpty()
  organizationName: string;
}
