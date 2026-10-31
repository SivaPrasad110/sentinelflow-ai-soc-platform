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

// ==========================================
// Phase 6: Threat Intelligence & IOC APIs
// ==========================================

export async function getIocs(params?: { query?: string; type?: string; severity?: string; limit?: number }) {
  const query = new URLSearchParams();
  if (params?.query) query.set('query', params.query);
  if (params?.type) query.set('type', params.type);
  if (params?.severity) query.set('severity', params.severity);
  if (params?.limit) query.set('limit', String(params.limit));

  const response = await secureFetch(`/api/v1/iocs?${query.toString()}`, { method: 'GET' });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to load indicators of compromise (HTTP ${response.status})`);
  }
  return response.json();
}

export async function getIocById(id: string) {
  const response = await secureFetch(`/api/v1/iocs/${id}`, { method: 'GET' });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to load IOC (HTTP ${response.status})`);
  }
  return response.json();
}

export async function createIoc(payload: any) {
  const response = await secureFetch('/api/v1/iocs', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to create IOC (HTTP ${response.status})`);
  }
  return response.json();
}

export async function deleteIoc(id: string) {
  const response = await secureFetch(`/api/v1/iocs/${id}`, { method: 'DELETE' });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to delete IOC (HTTP ${response.status})`);
  }
  return response.json();
}

export async function getThreatFeeds() {
  const response = await secureFetch('/api/v1/threat-intel/feeds', { method: 'GET' });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to load threat feeds (HTTP ${response.status})`);
  }
  return response.json();
}

export async function createThreatFeed(payload: any) {
  const response = await secureFetch('/api/v1/threat-intel/feeds', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to create threat feed (HTTP ${response.status})`);
  }
  return response.json();
}

export async function syncThreatFeed(feedId: string) {
  const response = await secureFetch(`/api/v1/threat-intel/feeds/${feedId}/sync`, { method: 'POST' });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to sync feed (HTTP ${response.status})`);
  }
  return response.json();
}

export async function getThreatIntelStats() {
  const response = await secureFetch('/api/v1/threat-intel/stats', { method: 'GET' });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to load threat intel stats (HTTP ${response.status})`);
  }
  return response.json();
}

// ==========================================
// Phase 6: Detection Engine & Rules APIs
// ==========================================

export async function getDetectionRules() {
  const response = await secureFetch('/api/v1/detection/rules', { method: 'GET' });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to load detection rules (HTTP ${response.status})`);
  }
  return response.json();
}

export async function getDetectionRuleById(id: string) {
  const response = await secureFetch(`/api/v1/detection/rules/${id}`, { method: 'GET' });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to load detection rule (HTTP ${response.status})`);
  }
  return response.json();
}

export async function createDetectionRule(payload: any) {
  const response = await secureFetch('/api/v1/detection/rules', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to create detection rule (HTTP ${response.status})`);
  }
  return response.json();
}

export async function updateDetectionRule(id: string, payload: any) {
  const response = await secureFetch(`/api/v1/detection/rules/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to update detection rule (HTTP ${response.status})`);
  }
  return response.json();
}

export async function toggleDetectionRule(id: string, enabled?: boolean) {
  const response = await secureFetch(`/api/v1/detection/rules/${id}/toggle`, {
    method: 'PATCH',
    body: JSON.stringify({ enabled }),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to toggle detection rule (HTTP ${response.status})`);
  }
  return response.json();
}

export async function deleteDetectionRule(id: string) {
  const response = await secureFetch(`/api/v1/detection/rules/${id}`, { method: 'DELETE' });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to delete detection rule (HTTP ${response.status})`);
  }
  return response.json();
}

export async function getMitreMatrix() {
  const response = await secureFetch('/api/v1/detection/mitre/matrix', { method: 'GET' });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to load MITRE ATT&CK matrix (HTTP ${response.status})`);
  }
  return response.json();
}

export async function getMitreTechniques() {
  const response = await secureFetch('/api/v1/detection/mitre/techniques', { method: 'GET' });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to load MITRE techniques (HTTP ${response.status})`);
  }
  return response.json();
}

// ==========================================
// Phase 6: Correlated Findings APIs
// ==========================================

export async function getFindings(params?: { status?: string; severity?: string }) {
  const query = new URLSearchParams();
  if (params?.status) query.set('status', params.status);
  if (params?.severity) query.set('severity', params.severity);

  const response = await secureFetch(`/api/v1/detection/findings?${query.toString()}`, { method: 'GET' });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to load findings (HTTP ${response.status})`);
  }
  return response.json();
}

export async function promoteFindingToIncident(findingId: string) {
  const response = await secureFetch(`/api/v1/detection/findings/${findingId}/promote`, {
    method: 'POST',
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to promote finding to incident (HTTP ${response.status})`);
  }
  return response.json();
}

export async function dismissFinding(findingId: string, reason?: string) {
  const response = await secureFetch(`/api/v1/detection/findings/${findingId}/dismiss`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `Failed to dismiss finding (HTTP ${response.status})`);
  }
  return response.json();
}
