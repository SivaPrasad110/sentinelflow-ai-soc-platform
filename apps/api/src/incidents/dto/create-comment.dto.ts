import { IsString, MinLength, MaxLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateCommentDto {
  @ApiProperty({
    description: 'Investigation note or comment from security analyst',
    example: 'Identified abnormal SMB traffic from workstation WS-FIN-04 to domain controller.',
    minLength: 1,
    maxLength: 2000,
  })
  @IsString()
  @MinLength(1)
  @MaxLength(2000)
  comment!: string;
}
