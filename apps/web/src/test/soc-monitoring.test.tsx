import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { SocAnalyticsView } from '../components/dashboard/SocAnalyticsView';
import { AuditLogsView } from '../components/dashboard/AuditLogsView';
import { IncidentsQueue } from '../components/dashboard/IncidentsQueue';
import * as ApiModule from '../services/api';
import * as AuthContextModule from '../context/AuthContext';
import type { SOCMetricsResponse, AuditLogRecord, Incident, IncidentTimelineEventRecord } from '@sentinelflow/shared';

const mockMetrics: SOCMetricsResponse = {
  overview: {
    totalIncidents: 12,
    openIncidents: 4,
    resolvedIncidents: 8,
    activeAlertsCount: 25,
    criticalIncidentsCount: 2,
    meanTimeToAcknowledgeMinutes: 8.5,
    meanTimeToResolveMinutes: 34.2,
  },
  severityDistribution: {
    CRITICAL: 2,
    HIGH: 4,
    MEDIUM: 5,
    LOW: 1,
  },
  statusDistribution: {
    NEW: 1,
    TRIAGED: 1,
    INVESTIGATING: 2,
    CONTAINED: 0,
    RESOLVED: 6,
    CLOSED: 2,
  },
  alertTrends: [
    { date: '2026-10-25', count: 3, critical: 1, high: 1, medium: 1, low: 0 },
    { date: '2026-10-26', count: 5, critical: 0, high: 2, medium: 2, low: 1 },
    { date: '2026-10-27', count: 4, critical: 1, high: 1, medium: 2, low: 0 },
  ],
  analystWorkload: [
    { analystId: 'usr-1', analystName: 'Sarah Chen', assignedCount: 3 },
    { analystId: 'usr-2', analystName: 'Alex Mercer', assignedCount: 1 },
  ],
};

const mockAuditLogs: AuditLogRecord[] = [
  {
    id: 'AUD-001',
    organizationId: 'org-1',
    userId: 'usr-1',
    userEmail: 'sarah.chen@sentinelflow.local',
    action: 'AUTH_LOGIN',
    entityType: 'AUTH',
    createdAt: new Date().toISOString(),
  },
  {
    id: 'AUD-002',
    organizationId: 'org-1',
    userId: 'usr-1',
    userEmail: 'sarah.chen@sentinelflow.local',
    action: 'INCIDENT_ASSIGN',
    entityType: 'INCIDENT',
    entityId: 'INC-2026-001',
    createdAt: new Date().toISOString(),
  },
];

const mockTimelineEvents: IncidentTimelineEventRecord[] = [
  {
    id: 'EVT-1',
    incidentId: 'INC-2026-001',
    organizationId: 'org-1',
    type: 'STATUS_CHANGE',
    message: 'Incident created with CRITICAL severity by system',
    createdAt: new Date().toISOString(),
  },
  {
    id: 'EVT-2',
    incidentId: 'INC-2026-001',
    organizationId: 'org-1',
    type: 'COMMENT',
    message: 'Memory forensics confirm LSASS injection',
    userName: 'Sarah Chen',
    userEmail: 'sarah.chen@sentinelflow.local',
    createdAt: new Date().toISOString(),
  },
];

const sampleIncident: Incident = {
  id: 'INC-2026-001',
  title: 'LSASS Memory Dumping Activity',
  description: 'Suspicious process injected into lsass.exe.',
  severity: 'CRITICAL',
  status: 'INVESTIGATING',
  organizationId: 'org-1',
  assignedTo: 'Sarah Chen',
  assignedToId: 'usr-1',
  assignedToEmail: 'sarah.chen@sentinelflow.local',
  iocs: [],
  analyses: [],
  sourceAlertIds: [],
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
};

describe('Phase 5 Advanced SOC Monitoring & Analytics UI', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(AuthContextModule, 'useAuth').mockReturnValue({
      user: { id: 'usr-1', name: 'Sarah Chen', email: 'sarah.chen@sentinelflow.local' } as any,
      activeRole: 'ANALYST',
      activeOrganization: { organizationId: 'org-1', organizationName: 'Sentinel Corp' } as any,
      token: 'mock-jwt-token',
      isAuthenticated: true,
      isLoading: false,
      login: vi.fn(),
      logout: vi.fn(),
      switchOrganization: vi.fn(),
    });
  });

  describe('SocAnalyticsView', () => {
    it('should render MTTA and MTTR KPI metric cards and severity breakdown', async () => {
      vi.spyOn(ApiModule, 'getSocMetrics').mockResolvedValue(mockMetrics);

      render(<SocAnalyticsView />);

      await waitFor(() => {
        expect(screen.getByText('Mean Time to Acknowledge')).toBeDefined();
        expect(screen.getByText('Mean Time to Resolve')).toBeDefined();
        expect(screen.getByText('8.5')).toBeDefined();
        expect(screen.getByText('34.2')).toBeDefined();
        expect(screen.getByText('12 total incidents tracked')).toBeDefined();
      });

      // Workload
      expect(screen.getByText('Sarah Chen')).toBeDefined();
      expect(screen.getByText('Alex Mercer')).toBeDefined();
    });
  });

  describe('AuditLogsView', () => {
    it('should render audit log stream with actor and action badges', async () => {
      vi.spyOn(ApiModule, 'getAuditLogs').mockResolvedValue(mockAuditLogs);

      render(<AuditLogsView />);

      await waitFor(() => {
        expect(screen.getByText('Immutable Security Audit Log')).toBeDefined();
        expect(screen.getAllByText('AUTH_LOGIN').length).toBeGreaterThan(0);
        expect(screen.getAllByText('INCIDENT_ASSIGN').length).toBeGreaterThan(0);
        expect(screen.getAllByText('sarah.chen@sentinelflow.local').length).toBeGreaterThan(0);
      });
    });
  });

  describe('Incident Timeline & Assignment Controls', () => {
    it('should render timeline events and allow posting investigation comments', async () => {
      vi.spyOn(AuthContextModule, 'useAuth').mockReturnValue({
        user: { id: 'usr-1', name: 'Sarah Chen', email: 'sarah.chen@sentinelflow.local' } as any,
        activeRole: 'ANALYST',
        activeOrganization: { organizationId: 'org-1', organizationName: 'Sentinel Corp' } as any,
        token: 'mock-jwt-token',
        isAuthenticated: true,
        isLoading: false,
        login: vi.fn(),
        logout: vi.fn(),
        switchOrganization: vi.fn(),
      });

      vi.spyOn(ApiModule, 'getIncidentTimeline').mockResolvedValue(mockTimelineEvents);
      vi.spyOn(ApiModule, 'getOrgMembers').mockResolvedValue([
        { id: 'mem-1', userId: 'usr-1', name: 'Sarah Chen', email: 'sarah.chen@sentinelflow.local', role: 'ANALYST' },
      ]);
      const addCommentSpy = vi.spyOn(ApiModule, 'addIncidentComment').mockResolvedValue({} as any);

      render(
        <IncidentsQueue
          incidents={[sampleIncident]}
          isLoading={false}
          error={null}
          onRefresh={vi.fn()}
          onCreateIncident={vi.fn()}
          onDeleteIncident={vi.fn()}
          selectedIncident={sampleIncident}
          onSelectIncident={vi.fn()}
        />,
      );

      await waitFor(() => {
        expect(screen.getByText('Investigation Timeline & Activity (2)')).toBeDefined();
        expect(screen.getByText('Memory forensics confirm LSASS injection')).toBeDefined();
      });

      // Find comment input and submit
      const commentInput = screen.getByPlaceholderText('Add investigation note or hypothesis...');
      fireEvent.change(commentInput, { target: { value: 'Discovered persistence via scheduled task' } });

      const postButton = screen.getByRole('button', { name: /Post/i });
      fireEvent.click(postButton);

      await waitFor(() => {
        expect(addCommentSpy).toHaveBeenCalledWith('INC-2026-001', 'Discovered persistence via scheduled task');
      });
    });
  });
});
