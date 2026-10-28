import { Module } from '@nestjs/common';
import { HealthController } from './health.controller';
import { HealthService } from './health.service';
import { N8nIntegrationModule } from '../n8n/n8n.module';

@Module({
  imports: [N8nIntegrationModule],
  controllers: [HealthController],
  providers: [HealthService],
  exports: [HealthService],
})
export class HealthModule {}
