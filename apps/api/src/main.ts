import { NestFactory } from '@nestjs/core';
import { Logger, ValidationPipe } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import * as cookieParser from 'cookie-parser';
import { AppModule } from './app.module';

async function bootstrap() {
  const logger = new Logger('SentinelFlowBootstrap');
  const app = await NestFactory.create(AppModule);

  const port = process.env.PORT || 3000;
  const corsOrigin = process.env.CORS_ORIGIN || 'http://localhost:5173';

  // Secure CORS with origin whitelisting & cookie credentials support
  app.enableCors({
    origin: corsOrigin,
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-organization-id', 'x-tenant-id'],
  });

  app.use(cookieParser());

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: false,
    }),
  );

  app.setGlobalPrefix('api/v1');

  // Swagger OpenAPI documentation
  const config = new DocumentBuilder()
    .setTitle('SentinelFlow API')
    .setDescription('Production-oriented AI Security Operations Platform REST API')
    .setVersion('1.0.0')
    .addTag('Authentication', 'Argon2id authentication, session management, and JWT tokens')
    .addTag('Health', 'System and external service health diagnostics')
    .addTag('Incidents', 'Multi-tenant security incident management and triage')
    .addTag('Alerts', 'Security alert ingestion and processing')
    .addBearerAuth()
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  await app.listen(port);
  logger.log(`SentinelFlow API is running on: http://localhost:${port}/api/v1`);
  logger.log(`Swagger documentation available at: http://localhost:${port}/api/docs`);
}

bootstrap();
