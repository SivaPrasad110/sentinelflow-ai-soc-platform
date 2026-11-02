import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { PrismaModule } from './prisma/prisma.module';
import { AuditModule } from './audit/audit.module';
import { EventsModule } from './events/events.module';
import { AuthModule } from './auth/auth.module';
import { HealthModule } from './health/health.module';
import { IncidentsModule } from './incidents/incidents.module';
import { AlertsModule } from './alerts/alerts.module';
import { N8nIntegrationModule } from './n8n/n8n.module';
import { AnalyticsModule } from './analytics/analytics.module';
import { IocModule } from './ioc/ioc.module';
import { ThreatIntelModule } from './threat-intel/threat-intel.module';
import { DetectionModule } from './detection/detection.module';
import { CorrelationIdMiddleware } from './common/middleware/correlation-id.middleware';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env.local', '.env', '../../.env'],
    }),
    ThrottlerModule.forRoot([
      {
        ttl: 60000,
        limit: 60, // Global limit 60 requests/minute
      },
    ]),
    PrismaModule,
    AuditModule,
    EventsModule,
    AuthModule,
    HealthModule,
    IncidentsModule,
    AlertsModule,
    N8nIntegrationModule,
    AnalyticsModule,
    IocModule,
    ThreatIntelModule,
    DetectionModule,
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    // O1: Attach correlation ID to every incoming request
    consumer.apply(CorrelationIdMiddleware).forRoutes('*');
  }
}

