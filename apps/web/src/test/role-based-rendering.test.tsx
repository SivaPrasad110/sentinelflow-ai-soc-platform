import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { IncidentsQueue } from '../components/dashboard/IncidentsQueue';
import { AuthContextType } from '../context/AuthContext';
import * as AuthContextModule from '../context/AuthContext';
import type { Incident } from '@sentinelflow/shared';

const sampleIncident: Incident = {
  id: 'INC-2026-001',
  title: 'Test Ransomware Incident',
  description: 'Test description for role-based rendering check',
  severity: 'CRITICAL',
  status: 'INVESTIGATING',
  organizationId: 'org-1',
  iocs: [],
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  sourceAlertIds: [],
};

describe('Role-Based UI Rendering Restrictions', () => {
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

  it('should restrict VIEWER role from creating and deleting incidents', () => {
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

    // Create Incident button should indicate read-only
    expect(screen.getByText(/Create \(Viewer: Read-only\)/i)).toBeInTheDocument();
    // Delete button should not exist
    expect(screen.queryByTitle(/Delete Incident/i)).not.toBeInTheDocument();
  });

  it('should allow ANALYST to create incidents but hide delete button', () => {
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

    // Create Incident button is enabled
    expect(screen.getByRole('button', { name: /Create Incident/i })).toBeInTheDocument();
    // Delete button should not exist for Analyst
    expect(screen.queryByTitle(/Delete Incident/i)).not.toBeInTheDocument();
  });

  it('should allow ADMIN to both create and delete incidents', () => {
    vi.spyOn(AuthContextModule, 'useAuth').mockReturnValue({
      activeRole: 'ADMIN',
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

    expect(screen.getByRole('button', { name: /Create Incident/i })).toBeInTheDocument();
    expect(screen.getByTitle(/Delete Incident \(Admin Only\)/i)).toBeInTheDocument();
  });
});
