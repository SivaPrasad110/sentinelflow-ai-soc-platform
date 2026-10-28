import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SystemHealthResponse } from '@sentinelflow/shared';

@Injectable()
export class HealthService {
  private readonly startTime = Date.now();

  constructor(private readonly configService: ConfigService) {}

  checkHealth(): SystemHealthResponse {
    const dbUrl = this.configService.get<string>('DATABASE_URL');
    const n8nUrl = this.configService.get<string>('N8N_WEBHOOK_URL');

    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptimeSeconds: Math.floor((Date.now() - this.startTime) / 1000),
      environment: this.configService.get<string>('NODE_ENV') || 'development',
      version: '0.1.0',
      services: {
        api: 'healthy',
        database: dbUrl ? 'connected' : 'unconfigured',
        n8n: n8nUrl ? 'connected' : 'unconfigured',
      },
    };
  }
}
