/**
 * SentinelFlow CORS Configuration & Validation Utilities
 *
 * Enforces strict origin whitelisting:
 * - Credentials (cookies, HTTP-only refresh tokens) are supported.
 * - Wildcards (*) and origin: true are explicitly prohibited with credentials.
 * - Server-to-server requests without an Origin header are safely allowed.
 * - Exact origin matching with trimming and trailing-slash normalization.
 */

export const REQUIRED_ALLOWED_ORIGINS: readonly string[] = [
  'https://sentinelflow-ai-soc-platform-beryl.vercel.app',
  'https://sentinelflow-api-ohio.onrender.com',
  'http://localhost:5173',
] as const;

/**
 * Safely parses and normalizes a comma-separated list of allowed origins.
 *
 * Features:
 * - Trims whitespace around each origin entry.
 * - Strips optional surrounding quotes (e.g. from environment variable definitions).
 * - Normalizes trailing slashes to ensure strict RFC 6454 origin comparison.
 * - Merges with REQUIRED_ALLOWED_ORIGINS so essential deployment domains are always permitted.
 * - Deduplicates the final origin array.
 */
export function parseAllowedOrigins(corsOriginEnv?: string): string[] {
  const customOrigins: string[] = [];

  if (corsOriginEnv) {
    // Strip surrounding quotes if the entire env var was quoted
    const unquoted = corsOriginEnv.trim().replace(/^['"]+|['"]+$/g, '');
    const tokens = unquoted.split(',');

    for (const token of tokens) {
      const cleaned = token
        .trim()
        .replace(/^['"]+|['"]+$/g, '')
        .trim()
        .replace(/\/+$/, '');

      if (cleaned) {
        customOrigins.push(cleaned);
      }
    }
  }

  const allOrigins = new Set<string>([
    ...REQUIRED_ALLOWED_ORIGINS.map((o) => o.replace(/\/+$/, '')),
    ...customOrigins,
  ]);

  return Array.from(allOrigins);
}

/**
 * Validates whether an incoming Origin header value is permitted.
 *
 * Rules:
 * - Undefined or empty origin -> allowed (server-to-server, curl, webhook callbacks, health checks).
 * - Exact match against whitelisted origins (normalizing any trailing slash).
 */
export function isOriginAllowed(origin: string | undefined, allowedOrigins: string[]): boolean {
  if (!origin) {
    return true;
  }

  const normalized = origin.trim().replace(/\/+$/, '');
  return allowedOrigins.includes(normalized);
}

/**
 * Creates the standard Express CORS origin callback for app.enableCors().
 */
export function createCorsOriginCallback(allowedOrigins: string[]) {
  return (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => {
    if (isOriginAllowed(origin, allowedOrigins)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS: Origin "${origin}" not allowed`));
    }
  };
}

/**
 * Creates the standard WebSocket CORS origin callback for @WebSocketGateway.
 */
export function createWsCorsOriginCallback(allowedOrigins: string[]) {
  return (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => {
    if (isOriginAllowed(origin, allowedOrigins)) {
      callback(null, true);
    } else {
      callback(new Error(`WebSocket CORS: origin "${origin}" not allowed`));
    }
  };
}
