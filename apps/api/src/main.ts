import { NestFactory } from '@nestjs/core';
import { Logger } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { AppModule } from './app.module';

async function bootstrap() {
  const logger = new Logger('SentinelFlowBootstrap');
  const app = await NestFactory.create(AppModule);

  const port = process.env.PORT || 3000;
  const corsOrigin = process.env.CORS_ORIGIN || 'http://localhost:5173';

  app.enableCors({
    origin: corsOrigin,
    credentials: true,
  });

  app.setGlobalPrefix('api/v1');

  // Swagger OpenAPI documentation
  const config = new DocumentBuilder()
    .setTitle('SentinelFlow API')
    .setDescription('Production-oriented AI Security Operations Platform REST API')
    .setVersion('1.0.0')
    .addTag('Health', 'System and external service health diagnostics')
    .addTag('Incidents', 'Security incident management and triage')
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
