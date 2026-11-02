import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { randomUUID } from 'crypto';

/**
 * O1 — Request Correlation ID Middleware
 *
 * Reads `X-Request-Id` from incoming headers or generates a fresh UUID v4.
 * Attaches the ID to `req.correlationId` for use in structured log lines,
 * and echoes it back as `X-Request-Id` in the response so callers can
 * trace the full request/response lifecycle.
 */
@Injectable()
export class CorrelationIdMiddleware implements NestMiddleware {
  use(req: Request & { correlationId?: string }, res: Response, next: NextFunction) {
    const existing = req.headers['x-request-id'] as string | undefined;
    const correlationId = existing || randomUUID();

    req.correlationId = correlationId;
    res.setHeader('X-Request-Id', correlationId);

    next();
  }
}
