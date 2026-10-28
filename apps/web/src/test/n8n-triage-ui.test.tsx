import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { IncidentsQueue } from '../components/dashboard/IncidentsQueue';
import * as AuthContextModule from '../context/AuthContext';
import * as ApiModule from '../services/api';
import type { Incident, IncidentAnalysisRecord } from '@sentinelflow/shared';

const mockAnalysis: IncidentAnalysisRecord = {
  id: 'ANALYSIS-101',
  incidentId: 'INC-2026-001',
  organizationId: 'org-1',
  status: 'COMPLETED',
  eventId: 'evt-test-888',
  summary: 'Automated AI triage completed. Suspected Mimikatz credential dumping detected.',
  severityAssessment: 'CRITICAL',
  confidence: 0.96,
  evidence: ['lsass.exe memory dump attempt', 'Unauthorized debug privilege enabled'],
  potentialImpact: 'Domain-wide credential compromise risk.',
  recommendedActions: [
    'Isolate workstation immediately via EDR agent',
    'Enforce emergency password reset for Enterprise Admins',
  ],
  missingInformation: ['Netflow connection logs for surrounding 30 minutes'],
  requiresHumanReview: true,
  durationMs: 1420,
  createdAt: new Date().toISOString(),
};

const sampleIncident: Incident = {
  id: 'INC-2026-001',
  title: 'LSASS Memory Dumping Activity',
  description: 'Suspicious process injected into lsass.exe.',
  severity: 'CRITICAL',
  status: 'NEW',
  organizationId: 'org-1',
  iocs: [{ id: 'ioc-1', type: 'IP', value: '203.0.113.15', createdAt: new Date().toISOString() }],
  analyses: [mockAnalysis],
  sourceAlertIds: [],
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
};

describe('n8n AI Incident Triage Dashboard Integration', () => {
  const mockProps = {
    incidents: [sampleIncident],
    isLoading: false,
    error: null,
    onRefresh: vi.fn(),
    onCreateIncident: vi.fn(),
    onDeleteIncident: vi.fn(),
    selectedIncident: sampleIncident,
    onSelectIncident: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should restrict VIEWER role from triggering AI triage', () => {
    vi.spyOn(AuthContextModule, 'useAuth').mockReturnValue({
      activeRole: 'VIEWER',
      user: null,
      activeOrganization: null,
      isAuthenticated: true,
      isLoading: false,
      authError: null,
      login: vi.fn(),
      logout: vi.fn(),
      switchOrganization: vi.fn(),
      clearError: vi.fn(),
    });

    render(<IncidentsQueue {...mockProps} />);

    // Analyze button should indicate read-only lock for viewer
    expect(screen.getByText(/Analyze \(Viewer: Read-only\)/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^Analyze Incident$/i })).not.toBeInTheDocument();
  });

  it('should allow ANALYST role to see and click Analyze Incident button', async () => {
    vi.spyOn(AuthContextModule, 'useAuth').mockReturnValue({
      activeRole: 'ANALYST',
      user: null,
      activeOrganization: null,
      isAuthenticated: true,
      isLoading: false,
      authError: null,
      login: vi.fn(),
      logout: vi.fn(),
      switchOrganization: vi.fn(),
      clearError: vi.fn(),
    });

    const triggerSpy = vi.spyOn(ApiModule, 'triggerIncidentAnalysis').mockResolvedValue(mockAnalysis);

    render(<IncidentsQueue {...mockProps} />);

    const analyzeBtn = screen.getByRole('button', { name: /Analyze Incident/i });
    expect(analyzeBtn).toBeInTheDocument();

    fireEvent.click(analyzeBtn);

    await waitFor(() => {
      expect(triggerSpy).toHaveBeenCalledWith('INC-2026-001');
      expect(mockProps.onRefresh).toHaveBeenCalled();
    });
  });

  it('should render all structured AI analysis fields accurately', () => {
    vi.spyOn(AuthContextModule, 'useAuth').mockReturnValue({
      activeRole: 'ANALYST',
      user: null,
      activeOrganization: null,
      isAuthenticated: true,
      isLoading: false,
      authError: null,
      login: vi.fn(),
      logout: vi.fn(),
      switchOrganization: vi.fn(),
      clearError: vi.fn(),
    });

    render(<IncidentsQueue {...mockProps} />);

    // Check summary
    expect(screen.getByText(/Suspected Mimikatz credential dumping detected/i)).toBeInTheDocument();

    // Check advisory human review callout
    expect(screen.getByText(/Advisory AI Assessment/i)).toBeInTheDocument();

    // Check confidence & advisory severity
    expect(screen.getByText(/Confidence: 96%/i)).toBeInTheDocument();
    expect(screen.getByText(/Advisory: CRITICAL/i)).toBeInTheDocument();

    // Check potential impact
    expect(screen.getByText(/Domain-wide credential compromise risk/i)).toBeInTheDocument();

    // Check evidence checklist
    expect(screen.getByText(/lsass.exe memory dump attempt/i)).toBeInTheDocument();

    // Check recommended defensive actions
    expect(screen.getByText(/Isolate workstation immediately via EDR agent/i)).toBeInTheDocument();

    // Check missing telemetry
    expect(screen.getByText(/Netflow connection logs for surrounding 30 minutes/i)).toBeInTheDocument();
  });

  it('should display error banner with retry option if analysis fails', async () => {
    vi.spyOn(AuthContextModule, 'useAuth').mockReturnValue({
      activeRole: 'ANALYST',
      user: null,
      activeOrganization: null,
      isAuthenticated: true,
      isLoading: false,
      authError: null,
      login: vi.fn(),
      logout: vi.fn(),
      switchOrganization: vi.fn(),
      clearError: vi.fn(),
    });

    vi.spyOn(ApiModule, 'triggerIncidentAnalysis').mockRejectedValue(
      new Error('n8n AI incident triage request timed out after 20 seconds.'),
    );

    render(<IncidentsQueue {...mockProps} />);

    const analyzeBtn = screen.getByRole('button', { name: /Analyze Incident/i });
    fireEvent.click(analyzeBtn);

    await waitFor(() => {
      expect(screen.getByText(/n8n AI incident triage request timed out/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Retry Analysis/i })).toBeInTheDocument();
    });
  });
});
