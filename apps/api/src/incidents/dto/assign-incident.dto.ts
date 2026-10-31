import { IsOptional, IsString } from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class AssignIncidentDto {
  @ApiPropertyOptional({
    description: 'User ID of analyst to assign incident to (null to unassign)',
    example: 'usr-analyst-001',
    nullable: true,
  })
  @IsOptional()
  @IsString()
  assignedToId?: string | null;
}
