import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SystemHealthResponse } from '@sentinelflow/shared';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class HealthService {
  private readonly startTime = Date.now();

  constructor(
    private readonly configService: ConfigService,
    private readonly prisma: PrismaService,
  ) {}

  async checkHealth(): Promise<SystemHealthResponse> {
    const n8nUrl = this.configService.get<string>('N8N_WEBHOOK_URL');
    const isDbConnected = await this.prisma.isHealthy();

    return {
      status: isDbConnected ? 'ok' : 'degraded',
      timestamp: new Date().toISOString(),
      uptimeSeconds: Math.floor((Date.now() - this.startTime) / 1000),
      environment: this.configService.get<string>('NODE_ENV') || 'development',
      version: '0.1.0',
      services: {
        api: 'healthy',
        database: isDbConnected ? 'connected' : 'disconnected',
        n8n: n8nUrl ? 'connected' : 'unconfigured',
      },
    };
  }
}
