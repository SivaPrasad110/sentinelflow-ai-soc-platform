import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import App from '../App';
import { setAccessToken, setActiveOrganizationId } from '../services/api';

describe('Organization Switcher & Cross-Tenant Data Isolation', () => {
  beforeEach(() => {
    setAccessToken(null);
    setActiveOrganizationId(null);
    vi.restoreAllMocks();
  });

  const mockUserMultiOrg = {
    id: 'USR-SOC-001',
    email: 'multi.analyst@sentinelflow.local',
    name: 'Multi-Tenant Analyst',
    activeOrganizationId: 'org-cyberdefense-001',
    activeRole: 'ANALYST',
    memberships: [
      {
        id: 'MEM-001',
        organizationId: 'org-cyberdefense-001',
        organizationName: 'CyberDefense SOC',
        organizationSlug: 'cyberdefense-soc',
        role: 'ANALYST',
      },
      {
        id: 'MEM-002',
        organizationId: 'org-secops-002',
        organizationName: 'SecOps Global',
        organizationSlug: 'secops-global',
        role: 'ADMIN',
      },
    ],
    createdAt: new Date().toISOString(),
  };

  it('should list verified memberships and refresh data when switching organization', async () => {
    let currentOrgHeader = 'org-cyberdefense-001';

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url: any, opts: any) => {
      const u = url.toString();
      const headers = opts?.headers instanceof Headers ? opts.headers : new Headers(opts?.headers || {});
      const orgIdHeader = headers.get('x-organization-id') || currentOrgHeader;

      if (u.includes('/auth/refresh')) {
        return new Response(JSON.stringify({ accessToken: 'access-token-123' }), { status: 200 });
      }
      if (u.includes('/auth/me')) {
        return new Response(
          JSON.stringify({
            ...mockUserMultiOrg,
            activeOrganizationId: orgIdHeader,
            activeRole: orgIdHeader === 'org-secops-002' ? 'ADMIN' : 'ANALYST',
          }),
          { status: 200 },
        );
      }
      if (u.includes('/incidents')) {
        if (orgIdHeader === 'org-secops-002') {
          return new Response(
            JSON.stringify([
              {
                id: 'INC-SECOPS-99',
                title: 'SecOps Global Incident',
                description: 'Confidential incident for SecOps Global',
                severity: 'HIGH',
                status: 'NEW',
                iocs: [],
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString(),
              },
            ]),
            { status: 200 },
          );
        }
        return new Response(
          JSON.stringify([
            {
              id: 'INC-CYBER-01',
              title: 'CyberDefense Incident',
              description: 'Primary SOC incident',
              severity: 'CRITICAL',
              status: 'INVESTIGATING',
              iocs: [],
              createdAt: new Date().toISOString(),
              updatedAt: new Date().toISOString(),
            },
          ]),
          { status: 200 },
        );
      }
      if (u.includes('/alerts')) {
        return new Response(JSON.stringify([]), { status: 200 });
      }
      if (u.includes('/health')) {
        return new Response(
          JSON.stringify({
            status: 'ok',
            services: { api: 'healthy', database: 'connected', n8n: 'connected' },
          }),
          { status: 200 },
        );
      }
      return new Response('{}', { status: 200 });
    });

    render(<App />);

    // Initially loads CyberDefense SOC and its incident
    const initialIncidents = await screen.findAllByText('CyberDefense Incident');
    expect(initialIncidents.length).toBeGreaterThan(0);
    expect(screen.getAllByText('CyberDefense SOC').length).toBeGreaterThan(0);
    expect(screen.queryByText('SecOps Global Incident')).not.toBeInTheDocument();

    // Open organization switcher dropdown
    const orgDropdownBtn = screen.getByRole('button', { name: /CyberDefense SOC/i });
    fireEvent.click(orgDropdownBtn);

    // Both server-verified organizations are listed
    expect(await screen.findByText('SecOps Global')).toBeInTheDocument();

    // Select SecOps Global
    currentOrgHeader = 'org-secops-002';
    const secOpsOption = screen.getByText('SecOps Global');
    fireEvent.click(secOpsOption);

    // Data should now strictly display SecOps Global incident and exclude CyberDefense data
    const switchedIncidents = await screen.findAllByText('SecOps Global Incident');
    expect(switchedIncidents.length).toBeGreaterThan(0);
    expect(screen.queryByText('CyberDefense Incident')).not.toBeInTheDocument();
  });
});
