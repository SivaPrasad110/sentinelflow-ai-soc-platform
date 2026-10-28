import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { PrismaModule } from '../prisma/prisma.module';
import { N8nIntegrationService } from './n8n.service';

@Module({
  imports: [ConfigModule, PrismaModule],
  providers: [N8nIntegrationService],
  exports: [N8nIntegrationService],
})
export class N8nIntegrationModule {}
