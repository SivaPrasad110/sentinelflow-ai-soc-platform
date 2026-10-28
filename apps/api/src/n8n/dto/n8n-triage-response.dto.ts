import {
  IsString,
  IsNumber,
  IsArray,
  IsBoolean,
  Min,
  Max,
  MinLength,
  MaxLength,
  ArrayMaxSize,
  Matches,
} from 'class-validator';

export class N8nTriageResponseDto {
  @IsString()
  @MinLength(5)
  @MaxLength(3000)
  summary!: string;

  @IsString()
  @Matches(/^(informational|low|medium|high|critical)$/i, {
    message: 'severity_assessment must be one of: informational, low, medium, high, critical',
  })
  severity_assessment!: string;

  @IsNumber()
  @Min(0.0)
  @Max(1.0)
  confidence!: number;

  @IsArray()
  @IsString({ each: true })
  @ArrayMaxSize(30)
  evidence!: string[];

  @IsString()
  @MaxLength(3000)
  potential_impact!: string;

  @IsArray()
  @IsString({ each: true })
  @ArrayMaxSize(30)
  recommended_actions!: string[];

  @IsArray()
  @IsString({ each: true })
  @ArrayMaxSize(30)
  missing_information!: string[];

  @IsBoolean()
  requires_human_review!: boolean;
}
