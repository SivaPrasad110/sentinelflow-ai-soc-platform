import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { HealthModule } from './health/health.module';
import { IncidentsModule } from './incidents/incidents.module';
import { AlertsModule } from './alerts/alerts.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env.local', '.env', '../../.env'],
    }),
    HealthModule,
    IncidentsModule,
    AlertsModule,
  ],
})
export class AppModule {}
