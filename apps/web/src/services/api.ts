/**
 * SentinelFlow Secure API Client
 * - Stores access tokens strictly in memory (never localStorage / sessionStorage)
 * - Uses credentials: 'include' for secure HTTP-only refresh cookie exchange
 * - Mutex-locked single-flight token refresh to prevent token rotation race conditions
 */

let inMemoryAccessToken: string | null = null;
let currentOrganizationId: string | null = null;
let refreshPromise: Promise<string | null> | null = null;
let onSessionExpiredCallback: (() => void) | null = null;

export function setAccessToken(token: string | null) {
  inMemoryAccessToken = token;
}

export function getAccessToken(): string | null {
  return inMemoryAccessToken;
}

export function setActiveOrganizationId(orgId: string | null) {
  currentOrganizationId = orgId;
}

export function getActiveOrganizationId(): string | null {
  return currentOrganizationId;
}

export function setSessionExpiredHandler(handler: () => void) {
  onSessionExpiredCallback = handler;
}

/**
 * Execute token refresh with single-flight promise locking.
 * Prevents concurrent 401s from racing and failing rotating refresh sessions.
 */
async function performTokenRefresh(): Promise<string | null> {
  try {
    const res = await fetch('/api/v1/auth/refresh', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      credentials: 'include', // sends HTTP-only refresh_token cookie
    });

    if (!res.ok) {
      inMemoryAccessToken = null;
      return null;
    }

    const data = await res.json();
    inMemoryAccessToken = data.accessToken;
    return data.accessToken;
  } catch {
    inMemoryAccessToken = null;
    return null;
  }
}

export async function secureFetch(url: string, options: RequestInit = {}): Promise<Response> {
  const headers = new Headers(options.headers || {});

  if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }

  if (inMemoryAccessToken && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${inMemoryAccessToken}`);
  }

  if (currentOrganizationId && !headers.has('x-organization-id')) {
    headers.set('x-organization-id', currentOrganizationId);
  }

  // Always include credentials for cookies (refresh tokens, session cookies)
  const fetchOptions: RequestInit = {
    ...options,
    headers,
    credentials: 'include',
  };

  let response = await fetch(url, fetchOptions);

  // If response is 401 Unauthorized, attempt atomic token refresh
  if (response.status === 401 && !url.includes('/auth/login') && !url.includes('/auth/refresh')) {
    if (!refreshPromise) {
      refreshPromise = performTokenRefresh().finally(() => {
        refreshPromise = null;
      });
    }

    const newAccessToken = await refreshPromise;

    if (newAccessToken) {
      // Retry original request with newly issued access token
      const retryHeaders = new Headers(options.headers || {});
      if (!retryHeaders.has('Content-Type') && !(options.body instanceof FormData)) {
        retryHeaders.set('Content-Type', 'application/json');
      }
      retryHeaders.set('Authorization', `Bearer ${newAccessToken}`);
      if (currentOrganizationId) {
        retryHeaders.set('x-organization-id', currentOrganizationId);
      }

      response = await fetch(url, {
        ...options,
        headers: retryHeaders,
        credentials: 'include',
      });
    } else {
      // Refresh token invalid or expired
      if (onSessionExpiredCallback) {
        onSessionExpiredCallback();
      }
    }
  }

  return response;
}

/**
 * Trigger AI incident triage via n8n Cloud
 */
export async function triggerIncidentAnalysis(incidentId: string) {
  const response = await secureFetch(`/api/v1/incidents/${incidentId}/analyze`, {
    method: 'POST',
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to analyze incident (HTTP ${response.status})`);
  }

  return response.json();
}

/**
 * Retrieve analysis history for an incident
 */
export async function getIncidentAnalyses(incidentId: string) {
  const response = await secureFetch(`/api/v1/incidents/${incidentId}/analyses`, {
    method: 'GET',
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to fetch incident analyses (HTTP ${response.status})`);
  }

  return response.json();
}

/**
 * Fetch SOC metrics, MTTA, MTTR, and trends
 */
export async function getSocMetrics() {
  const response = await secureFetch('/api/v1/analytics/soc-metrics', {
    method: 'GET',
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to fetch SOC metrics (HTTP ${response.status})`);
  }

  return response.json();
}

/**
 * Assign incident to analyst
 */
export async function assignIncident(incidentId: string, assignedToId: string | null) {
  const response = await secureFetch(`/api/v1/incidents/${incidentId}/assign`, {
    method: 'PATCH',
    body: JSON.stringify({ assignedToId }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to assign incident (HTTP ${response.status})`);
  }

  return response.json();
}

/**
 * Update incident status
 */
export async function updateIncidentStatus(incidentId: string, status: string) {
  const response = await secureFetch(`/api/v1/incidents/${incidentId}`, {
    method: 'PATCH',
    body: JSON.stringify({ status }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to update status (HTTP ${response.status})`);
  }

  return response.json();
}

/**
 * Fetch incident investigation timeline
 */
export async function getIncidentTimeline(incidentId: string) {
  const response = await secureFetch(`/api/v1/incidents/${incidentId}/timeline`, {
    method: 'GET',
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to load timeline (HTTP ${response.status})`);
  }

  return response.json();
}

/**
 * Add comment to incident investigation timeline
 */
export async function addIncidentComment(incidentId: string, comment: string) {
  const response = await secureFetch(`/api/v1/incidents/${incidentId}/comments`, {
    method: 'POST',
    body: JSON.stringify({ comment }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to add comment (HTTP ${response.status})`);
  }

  return response.json();
}

/**
 * Fetch verified members of active organization
 */
export async function getOrgMembers() {
  const response = await secureFetch('/api/v1/incidents/members', {
    method: 'GET',
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to fetch organization members (HTTP ${response.status})`);
  }

  return response.json();
}

/**
 * Fetch security audit logs
 */
export async function getAuditLogs(limit = 50, action?: string) {
  const query = new URLSearchParams({ limit: String(limit) });
  if (action) query.set('action', action);

  const response = await secureFetch(`/api/v1/audit-logs?${query.toString()}`, {
    method: 'GET',
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to load audit logs (HTTP ${response.status})`);
  }

  return response.json();
}
