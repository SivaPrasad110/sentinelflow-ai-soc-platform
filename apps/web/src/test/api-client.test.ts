import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  setAccessToken,
  getAccessToken,
  setActiveOrganizationId,
  getActiveOrganizationId,
  secureFetch,
} from '../services/api';

describe('Secure API Client & Token Management', () => {
  beforeEach(() => {
    setAccessToken(null);
    setActiveOrganizationId(null);
    vi.restoreAllMocks();
  });

  it('should store access token strictly in memory', () => {
    setAccessToken('test-in-memory-token');
    expect(getAccessToken()).toBe('test-in-memory-token');

    // Verify localStorage & sessionStorage are NEVER touched
    expect(localStorage.getItem('access_token')).toBeNull();
    expect(sessionStorage.getItem('access_token')).toBeNull();
  });

  it('should automatically attach Authorization and x-organization-id headers', async () => {
    setAccessToken('jwt-access-token-123');
    setActiveOrganizationId('org-cyberdefense-001');

    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), { status: 200 }),
    );

    await secureFetch('/api/v1/incidents');

    expect(fetchSpy).toHaveBeenCalledWith(
      '/api/v1/incidents',
      expect.objectContaining({
        headers: expect.any(Headers),
        credentials: 'include',
      }),
    );

    const calledHeaders = fetchSpy.mock.calls[0][1]?.headers as Headers;
    expect(calledHeaders.get('Authorization')).toBe('Bearer jwt-access-token-123');
    expect(calledHeaders.get('x-organization-id')).toBe('org-cyberdefense-001');
  });

  it('should coalesce concurrent 401s into a single token refresh request (mutex lock)', async () => {
    setAccessToken('expired-token');

    let refreshCalls = 0;

    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url: any) => {
      const urlStr = url.toString();
      if (urlStr.includes('/auth/refresh')) {
        refreshCalls++;
        return new Response(JSON.stringify({ accessToken: 'new-rotated-token' }), { status: 200 });
      }
      if (urlStr.includes('/incidents')) {
        return new Response(JSON.stringify([{ id: 'inc-1' }]), { status: 200 });
      }
      return new Response('{}', { status: 200 });
    });

    // Simulate 3 concurrent API requests hitting expired token simultaneously
    // Mock the initial calls returning 401
    let callCount = 0;
    fetchSpy.mockImplementation(async (url: any) => {
      const urlStr = url.toString();
      if (urlStr.includes('/auth/refresh')) {
        refreshCalls++;
        return new Response(JSON.stringify({ accessToken: 'new-rotated-token' }), { status: 200 });
      }
      callCount++;
      // First 3 calls fail with 401
      if (callCount <= 3) {
        return new Response(JSON.stringify({ message: 'Unauthorized' }), { status: 401 });
      }
      // Retried calls succeed with 200
      return new Response(JSON.stringify({ success: true }), { status: 200 });
    });

    const [res1, res2, res3] = await Promise.all([
      secureFetch('/api/v1/incidents'),
      secureFetch('/api/v1/alerts'),
      secureFetch('/api/v1/health'),
    ]);

    // Crucial: Despite 3 concurrent 401s, only 1 refresh call was dispatched!
    expect(refreshCalls).toBe(1);
    expect(getAccessToken()).toBe('new-rotated-token');
  });
});
