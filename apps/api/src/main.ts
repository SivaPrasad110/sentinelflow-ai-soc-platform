import { NestFactory } from '@nestjs/core';
import { Logger, ValidationPipe } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import * as cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { AppModule } from './app.module';

async function bootstrap() {
  const logger = new Logger('SentinelFlowBootstrap');
  const app = await NestFactory.create(AppModule);

  const port = process.env.PORT || 3000;
  const corsOrigin = process.env.CORS_ORIGIN || 'http://localhost:5173';

  // ── Security Headers (Helmet) ──────────────────────────────────────────────
  // Must be registered before CORS and routes.
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:', 'https:'],
          connectSrc: ["'self'"],
          frameSrc: ["'none'"],
          objectSrc: ["'none'"],
          upgradeInsecureRequests: [],
        },
      },
      // HSTS: enforce HTTPS for 1 year (production only — NGINX handles this in dev)
      hsts: process.env.NODE_ENV === 'production'
        ? { maxAge: 31536000, includeSubDomains: true, preload: true }
        : false,
      crossOriginEmbedderPolicy: false, // required for Swagger UI
    }),
  );

  // ── CORS (origin whitelist — never wildcard) ────────────────────────────────
  // S2 fix: CORS_ORIGIN must be set explicitly; no wildcard fallback in prod.
  app.enableCors({
    origin: (origin, callback) => {
      // Allow same-origin requests (no origin header) and exact whitelisted origins
      const allowed = corsOrigin.split(',').map((o) => o.trim());
      if (!origin || allowed.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error(`CORS: Origin "${origin}" not allowed`));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-organization-id', 'x-tenant-id'],
  });

  app.use(cookieParser());

  // ── Request Validation ──────────────────────────────────────────────────────
  // S1 fix: forbidNonWhitelisted=true rejects requests with undeclared DTO fields.
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: true,
      transformOptions: { enableImplicitConversion: true },
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
