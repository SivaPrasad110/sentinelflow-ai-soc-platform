import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SystemHealthResponse } from '@sentinelflow/shared';
import { PrismaService } from '../prisma/prisma.service';
import { N8nIntegrationService } from '../n8n/n8n.service';

@Injectable()
export class HealthService {
  private readonly startTime = Date.now();

  constructor(
    private readonly configService: ConfigService,
    private readonly prisma: PrismaService,
    private readonly n8nService: N8nIntegrationService,
  ) {}

  async checkHealth(): Promise<SystemHealthResponse> {
    const isDbConnected = await this.prisma.isHealthy();
    const n8nStatus = await this.n8nService.checkConnectivity();

    return {
      status: isDbConnected ? 'ok' : 'degraded',
      timestamp: new Date().toISOString(),
      uptimeSeconds: Math.floor((Date.now() - this.startTime) / 1000),
      environment: this.configService.get<string>('NODE_ENV') || 'development',
      version: '0.1.0',
      services: {
        api: 'healthy',
        database: isDbConnected ? 'connected' : 'disconnected',
        n8n: n8nStatus,
      },
    };
  }
}
