import { Module, forwardRef } from '@nestjs/common';
import { DetectionController } from './detection.controller';
import { DetectionService } from './detection.service';
import { MitreAttackService } from './mitre/mitre-attack.service';
import { RiskScoringService } from './risk-scoring/risk-scoring.service';
import { IncidentsModule } from '../incidents/incidents.module';

@Module({
  imports: [forwardRef(() => IncidentsModule)],
  controllers: [DetectionController],
  providers: [DetectionService, MitreAttackService, RiskScoringService],
  exports: [DetectionService, MitreAttackService, RiskScoringService],
})
export class DetectionModule {}
