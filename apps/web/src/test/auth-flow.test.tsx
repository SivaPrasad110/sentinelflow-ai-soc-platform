import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import App from '../App';
import { setAccessToken, setActiveOrganizationId } from '../services/api';

describe('Frontend Authentication Flow', () => {
  beforeEach(() => {
    setAccessToken(null);
    setActiveOrganizationId(null);
    vi.restoreAllMocks();
  });

  it('should render the SOC Login page when unauthenticated', async () => {
    // Initial refresh fails (no session)
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url: any) => {
      const u = url.toString();
      if (u.includes('/auth/refresh')) {
        return new Response('{}', { status: 401 });
      }
      return new Response('{}', { status: 200 });
    });

    render(<App />);

    // Wait for the login button to render after session check completes
    expect(await screen.findByRole('button', { name: /Authenticate to SOC/i })).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/analyst@sentinelflow.local/i)).toBeInTheDocument();
  });

  it('should authenticate successfully with valid credentials and render SOC dashboard', async () => {
    const mockUser = {
      id: 'USR-SOC-001',
      email: 'sarah.chen@sentinelflow.local',
      name: 'Sarah Chen',
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
      ],
      createdAt: new Date().toISOString(),
    };

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url: any) => {
      const u = url.toString();
      if (u.includes('/auth/refresh')) {
        return new Response('{}', { status: 401 });
      }
      if (u.includes('/auth/login')) {
        return new Response(
          JSON.stringify({
            accessToken: 'mock-access-token',
            user: mockUser,
          }),
          { status: 200 },
        );
      }
      if (u.includes('/incidents')) {
        return new Response(
          JSON.stringify([
            {
              id: 'INC-2026-001',
              title: 'Suspicious PowerShell Execution',
              description: 'Telemetry detected Mimikatz execution',
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

    // Click quick fill for Analyst
    const analystBtn = await screen.findByRole('button', { name: /Sarah Chen/i });
    fireEvent.click(analystBtn);

    const submitBtn = screen.getByRole('button', { name: /Authenticate to SOC/i });
    fireEvent.click(submitBtn);

    // Dashboard should render with Sarah Chen and active role ANALYST
    expect(await screen.findByText('Sarah Chen')).toBeInTheDocument();
    expect(screen.getAllByText('ANALYST').length).toBeGreaterThan(0);
    expect(screen.getAllByText('CyberDefense SOC').length).toBeGreaterThan(0);
    expect(await screen.findAllByText('Suspicious PowerShell Execution')).toHaveLength(2);
  });

  it('should display error message on failed login attempt', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url: any) => {
      const u = url.toString();
      if (u.includes('/auth/refresh')) {
        return new Response('{}', { status: 401 });
      }
      if (u.includes('/auth/login')) {
        return new Response(
          JSON.stringify({ message: 'Invalid email or password.' }),
          { status: 401 },
        );
      }
      return new Response('{}', { status: 200 });
    });

    render(<App />);

    const emailInput = await screen.findByPlaceholderText(/analyst@sentinelflow.local/i);
    const passInput = screen.getByPlaceholderText(/••••••••••••/i);

    fireEvent.change(emailInput, { target: { value: 'wrong@user.com' } });
    fireEvent.change(passInput, { target: { value: 'WrongPass!' } });

    const submitBtn = screen.getByRole('button', { name: /Authenticate to SOC/i });
    fireEvent.click(submitBtn);

    expect(await screen.findByText(/Invalid email or password/i)).toBeInTheDocument();
  });
});
