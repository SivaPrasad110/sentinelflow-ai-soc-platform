import {
  REQUIRED_ALLOWED_ORIGINS,
  parseAllowedOrigins,
  isOriginAllowed,
  createCorsOriginCallback,
  createWsCorsOriginCallback,
} from './cors.utils';

describe('CORS Configuration & Origin Validation (cors.utils)', () => {
  describe('REQUIRED_ALLOWED_ORIGINS', () => {
    it('should include the production Vercel frontend', () => {
      expect(REQUIRED_ALLOWED_ORIGINS).toContain(
        'https://sentinelflow-ai-soc-platform-beryl.vercel.app',
      );
    });

    it('should include the production Render backend origin', () => {
      expect(REQUIRED_ALLOWED_ORIGINS).toContain(
        'https://sentinelflow-api-ohio.onrender.com',
      );
    });

    it('should include local development Vite origin', () => {
      expect(REQUIRED_ALLOWED_ORIGINS).toContain('http://localhost:5173');
    });
  });

  describe('parseAllowedOrigins', () => {
    it('should return required origins when env var is undefined or empty', () => {
      const origins1 = parseAllowedOrigins(undefined);
      expect(origins1).toEqual(expect.arrayContaining([...REQUIRED_ALLOWED_ORIGINS]));

      const origins2 = parseAllowedOrigins('');
      expect(origins2).toEqual(expect.arrayContaining([...REQUIRED_ALLOWED_ORIGINS]));
    });

    it('should parse comma-separated origins and trim whitespace', () => {
      const input = ' https://custom-soc.corp.local , https://analytics.corp.local ';
      const parsed = parseAllowedOrigins(input);

      expect(parsed).toContain('https://custom-soc.corp.local');
      expect(parsed).toContain('https://analytics.corp.local');
      expect(parsed).toContain('https://sentinelflow-api-ohio.onrender.com');
      expect(parsed).toContain('https://sentinelflow-ai-soc-platform-beryl.vercel.app');
    });

    it('should strip surrounding quotes from env string and individual tokens', () => {
      const input = '"https://quoted-domain.com", \'https://single-quoted.com\'';
      const parsed = parseAllowedOrigins(input);

      expect(parsed).toContain('https://quoted-domain.com');
      expect(parsed).toContain('https://single-quoted.com');
    });

    it('should normalize trailing slashes from configured origins', () => {
      const input = 'https://custom-trailing-slash.com/ , https://sentinelflow-api-ohio.onrender.com/';
      const parsed = parseAllowedOrigins(input);

      expect(parsed).toContain('https://custom-trailing-slash.com');
      expect(parsed).not.toContain('https://custom-trailing-slash.com/');
    });

    it('should deduplicate origins and ignore empty tokens', () => {
      const input = 'https://sentinelflow-api-ohio.onrender.com,,  ,http://localhost:5173,';
      const parsed = parseAllowedOrigins(input);

      const count = parsed.filter((o) => o === 'https://sentinelflow-api-ohio.onrender.com').length;
      expect(count).toBe(1);
      expect(parsed).not.toContain('');
    });
  });

  describe('isOriginAllowed', () => {
    const allowed = parseAllowedOrigins('https://custom-allowed.com');

    it('should allow requests without an Origin header (server-to-server, curl, health checks)', () => {
      expect(isOriginAllowed(undefined, allowed)).toBe(true);
      expect(isOriginAllowed('', allowed)).toBe(true);
    });

    it('should allow exact match of Vercel production frontend', () => {
      expect(
        isOriginAllowed(
          'https://sentinelflow-ai-soc-platform-beryl.vercel.app',
          allowed,
        ),
      ).toBe(true);
    });

    it('should allow exact match of Render backend origin (Swagger UI / self calls)', () => {
      expect(
        isOriginAllowed('https://sentinelflow-api-ohio.onrender.com', allowed),
      ).toBe(true);
    });

    it('should allow local development origin', () => {
      expect(isOriginAllowed('http://localhost:5173', allowed)).toBe(true);
    });

    it('should allow incoming origin with a trailing slash by normalising it', () => {
      expect(
        isOriginAllowed('https://sentinelflow-api-ohio.onrender.com/', allowed),
      ).toBe(true);
    });

    it('should reject unwhitelisted origins', () => {
      expect(isOriginAllowed('https://malicious-attacker.com', allowed)).toBe(false);
      expect(isOriginAllowed('http://localhost:3000', allowed)).toBe(false);
      expect(isOriginAllowed('https://evil.corp', allowed)).toBe(false);
    });

    it('should reject subdomain or prefix/suffix spoofed origins', () => {
      expect(
        isOriginAllowed(
          'https://sentinelflow-api-ohio.onrender.com.evil.com',
          allowed,
        ),
      ).toBe(false);
      expect(
        isOriginAllowed(
          'https://fake-sentinelflow-api-ohio.onrender.com',
          allowed,
        ),
      ).toBe(false);
      expect(
        isOriginAllowed(
          'https://sentinelflow-ai-soc-platform-beryl.vercel.app.attacker.com',
          allowed,
        ),
      ).toBe(false);
    });
  });

  describe('createCorsOriginCallback', () => {
    const allowed = parseAllowedOrigins();
    const callbackFn = createCorsOriginCallback(allowed);

    it('should invoke callback with (null, true) when origin is allowed', (done) => {
      callbackFn('https://sentinelflow-api-ohio.onrender.com', (err, allow) => {
        expect(err).toBeNull();
        expect(allow).toBe(true);
        done();
      });
    });

    it('should invoke callback with (null, true) when origin is undefined', (done) => {
      callbackFn(undefined, (err, allow) => {
        expect(err).toBeNull();
        expect(allow).toBe(true);
        done();
      });
    });

    it('should invoke callback with Error when origin is not allowed', (done) => {
      callbackFn('https://unauthorized-domain.com', (err, allow) => {
        expect(err).toBeInstanceOf(Error);
        expect(err?.message).toBe('CORS: Origin "https://unauthorized-domain.com" not allowed');
        expect(allow).toBeUndefined();
        done();
      });
    });
  });

  describe('createWsCorsOriginCallback', () => {
    const allowed = parseAllowedOrigins();
    const wsCallbackFn = createWsCorsOriginCallback(allowed);

    it('should invoke callback with (null, true) for allowed WebSocket origin', (done) => {
      wsCallbackFn(
        'https://sentinelflow-ai-soc-platform-beryl.vercel.app',
        (err, allow) => {
          expect(err).toBeNull();
          expect(allow).toBe(true);
          done();
        },
      );
    });

    it('should invoke callback with (null, true) when WebSocket origin is undefined', (done) => {
      wsCallbackFn(undefined, (err, allow) => {
        expect(err).toBeNull();
        expect(allow).toBe(true);
        done();
      });
    });

    it('should invoke callback with Error for rejected WebSocket origin', (done) => {
      wsCallbackFn('https://malicious-ws-client.com', (err, allow) => {
        expect(err).toBeInstanceOf(Error);
        expect(err?.message).toBe(
          'WebSocket CORS: origin "https://malicious-ws-client.com" not allowed',
        );
        expect(allow).toBeUndefined();
        done();
      });
    });
  });
});
