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
    expect(screen.getByRole('button', { name: /Register SOC/i })).toBeInTheDocument();
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

    // Type credentials directly into input fields
    const emailInput = await screen.findByPlaceholderText(/analyst@sentinelflow.local/i);
    const passInput = screen.getByPlaceholderText(/••••••••••••/i);

    fireEvent.change(emailInput, { target: { value: 'sarah.chen@sentinelflow.local' } });
    fireEvent.change(passInput, { target: { value: 'AnalystPassword123!' } });

    const submitBtn = screen.getByRole('button', { name: /Authenticate to SOC/i });
    fireEvent.click(submitBtn);

    // Dashboard should render with Sarah Chen and active role ANALYST
    expect(await screen.findByText('Sarah Chen')).toBeInTheDocument();
    expect(screen.getAllByText('ANALYST').length).toBeGreaterThan(0);
    expect(screen.getAllByText('CyberDefense SOC').length).toBeGreaterThan(0);
    expect(await screen.findAllByText('Suspicious PowerShell Execution')).toHaveLength(2);
  });

  it('should toggle password visibility on Login page', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url: any) => {
      const u = url.toString();
      if (u.includes('/auth/refresh')) {
        return new Response('{}', { status: 401 });
      }
      return new Response('{}', { status: 200 });
    });

    render(<App />);

    const passInput = await screen.findByPlaceholderText(/••••••••••••/i);
    expect(passInput).toHaveAttribute('type', 'password');

    const toggleBtn = screen.getByRole('button', { name: /Show password/i });
    fireEvent.click(toggleBtn);
    expect(passInput).toHaveAttribute('type', 'text');

    const hideBtn = screen.getByRole('button', { name: /Hide password/i });
    fireEvent.click(hideBtn);
    expect(passInput).toHaveAttribute('type', 'password');
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

  it('should display rate limit error on HTTP 429 response', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url: any) => {
      const u = url.toString();
      if (u.includes('/auth/refresh')) {
        return new Response('{}', { status: 401 });
      }
      if (u.includes('/auth/login')) {
        return new Response('Too many requests', { status: 429 });
      }
      return new Response('{}', { status: 200 });
    });

    render(<App />);

    const emailInput = await screen.findByPlaceholderText(/analyst@sentinelflow.local/i);
    const passInput = screen.getByPlaceholderText(/••••••••••••/i);

    fireEvent.change(emailInput, { target: { value: 'analyst@sentinelflow.local' } });
    fireEvent.change(passInput, { target: { value: 'Password123!' } });

    const submitBtn = screen.getByRole('button', { name: /Authenticate to SOC/i });
    fireEvent.click(submitBtn);

    expect(await screen.findByText(/Rate limit exceeded/i)).toBeInTheDocument();
  });

  it('should display friendly network error when backend is unreachable', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url: any) => {
      const u = url.toString();
      if (u.includes('/auth/refresh')) {
        return new Response('{}', { status: 401 });
      }
      if (u.includes('/auth/login')) {
        throw new TypeError('Failed to fetch');
      }
      return new Response('{}', { status: 200 });
    });

    render(<App />);

    const emailInput = await screen.findByPlaceholderText(/analyst@sentinelflow.local/i);
    const passInput = screen.getByPlaceholderText(/••••••••••••/i);

    fireEvent.change(emailInput, { target: { value: 'analyst@sentinelflow.local' } });
    fireEvent.change(passInput, { target: { value: 'Password123!' } });

    const submitBtn = screen.getByRole('button', { name: /Authenticate to SOC/i });
    fireEvent.click(submitBtn);

    expect(await screen.findByText(/Unable to connect to SentinelFlow API/i)).toBeInTheDocument();
  });

  it('should navigate from Login to Register page and back to Login', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url: any) => {
      const u = url.toString();
      if (u.includes('/auth/refresh')) {
        return new Response('{}', { status: 401 });
      }
      return new Response('{}', { status: 200 });
    });

    render(<App />);

    // Click Register SOC link
    const registerLink = await screen.findByRole('button', { name: /Register SOC/i });
    fireEvent.click(registerLink);

    // Verify Register page is displayed
    expect(await screen.findByText(/SOC ONBOARDING/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Sarah Chen/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/CyberDefense Operations/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Register Organization & Admin/i })).toBeInTheDocument();

    // Click Sign in to SOC to go back
    const signInLink = screen.getByRole('button', { name: /Sign in to SOC/i });
    fireEvent.click(signInLink);

    // Verify back on Login page
    expect(await screen.findByRole('button', { name: /Authenticate to SOC/i })).toBeInTheDocument();
  });

  it('should validate password complexity and matching confirmation on Register page', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url: any) => {
      const u = url.toString();
      if (u.includes('/auth/refresh')) {
        return new Response('{}', { status: 401 });
      }
      return new Response('{}', { status: 200 });
    });

    render(<App />);

    // Navigate to Register
    const registerLink = await screen.findByRole('button', { name: /Register SOC/i });
    fireEvent.click(registerLink);

    const nameInput = await screen.findByPlaceholderText(/Sarah Chen/i);
    const emailInput = screen.getByPlaceholderText(/analyst@sentinelflow.local/i);
    const orgInput = screen.getByPlaceholderText(/CyberDefense Operations/i);
    const submitBtn = screen.getByRole('button', { name: /Register Organization & Admin/i });

    fireEvent.change(nameInput, { target: { value: 'Alex Mercer' } });
    fireEvent.change(emailInput, { target: { value: 'alex@sentinelflow.local' } });
    fireEvent.change(orgInput, { target: { value: 'Global Threat Unit' } });

    // Submit button should be disabled until password criteria and match are satisfied
    expect(submitBtn).toBeDisabled();

    // Type weak password
    const passInputs = screen.getAllByPlaceholderText(/••••••••••••/i);
    const passInput = passInputs[0];
    const confirmInput = passInputs[1];

    fireEvent.change(passInput, { target: { value: 'weak' } });
    fireEvent.change(confirmInput, { target: { value: 'different' } });

    expect(screen.getByText(/Passwords do not match/i)).toBeInTheDocument();
    expect(submitBtn).toBeDisabled();

    // Type strong matching password (min 10 chars, uppercase, lowercase, number, symbol)
    fireEvent.change(passInput, { target: { value: 'Valid@Pass1234' } });
    fireEvent.change(confirmInput, { target: { value: 'Valid@Pass1234' } });

    expect(screen.getByText(/Passwords match/i)).toBeInTheDocument();
    expect(submitBtn).not.toBeDisabled();
  });

  it('should register organization and admin successfully and transition immediately to SOC dashboard', async () => {
    const mockRegisteredUser = {
      id: 'USR-SOC-ADMIN-01',
      email: 'admin@apex-defense.com',
      name: 'Apex Admin',
      activeOrganizationId: 'org-apex-001',
      activeRole: 'ADMIN',
      memberships: [
        {
          id: 'MEM-APEX-01',
          organizationId: 'org-apex-001',
          organizationName: 'Apex Defense',
          organizationSlug: 'apex-defense',
          role: 'ADMIN',
        },
      ],
      createdAt: new Date().toISOString(),
    };

    let registerCalled = false;
    let registerBody: any = null;

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url: any, options: any) => {
      const u = url.toString();
      if (u.includes('/auth/refresh')) {
        return new Response('{}', { status: 401 });
      }
      if (u.includes('/auth/register')) {
        registerCalled = true;
        registerBody = JSON.parse(options.body);
        return new Response(
          JSON.stringify({
            accessToken: 'apex-admin-token',
            user: mockRegisteredUser,
          }),
          { status: 201 },
        );
      }
      if (u.includes('/incidents')) {
        return new Response(JSON.stringify([]), { status: 200 });
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

    // Navigate to Register
    const registerLink = await screen.findByRole('button', { name: /Register SOC/i });
    fireEvent.click(registerLink);

    const nameInput = await screen.findByPlaceholderText(/Sarah Chen/i);
    const emailInput = screen.getByPlaceholderText(/analyst@sentinelflow.local/i);
    const orgInput = screen.getByPlaceholderText(/CyberDefense Operations/i);
    const passInputs = screen.getAllByPlaceholderText(/••••••••••••/i);

    fireEvent.change(nameInput, { target: { value: 'Apex Admin' } });
    fireEvent.change(emailInput, { target: { value: 'admin@apex-defense.com' } });
    fireEvent.change(orgInput, { target: { value: 'Apex Defense' } });
    fireEvent.change(passInputs[0], { target: { value: 'SecurePass@2026' } });
    fireEvent.change(passInputs[1], { target: { value: 'SecurePass@2026' } });

    const submitBtn = screen.getByRole('button', { name: /Register Organization & Admin/i });
    expect(submitBtn).not.toBeDisabled();
    fireEvent.click(submitBtn);

    // Wait for transition to Dashboard
    await waitFor(() => {
      expect(registerCalled).toBe(true);
    });

    expect(registerBody).toEqual({
      name: 'Apex Admin',
      email: 'admin@apex-defense.com',
      password: 'SecurePass@2026',
      organizationName: 'Apex Defense',
    });

    // Should render Dashboard with Apex Admin and ADMIN role without needing second login
    expect(await screen.findByText('Apex Admin')).toBeInTheDocument();
    expect(screen.getAllByText('ADMIN').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Apex Defense').length).toBeGreaterThan(0);
  });

  it('should display error notice on duplicate registration (HTTP 409)', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url: any) => {
      const u = url.toString();
      if (u.includes('/auth/refresh')) {
        return new Response('{}', { status: 401 });
      }
      if (u.includes('/auth/register')) {
        return new Response(
          JSON.stringify({ message: 'An account with this email address already exists.' }),
          { status: 409 },
        );
      }
      return new Response('{}', { status: 200 });
    });

    render(<App />);

    // Navigate to Register
    const registerLink = await screen.findByRole('button', { name: /Register SOC/i });
    fireEvent.click(registerLink);

    const nameInput = await screen.findByPlaceholderText(/Sarah Chen/i);
    const emailInput = screen.getByPlaceholderText(/analyst@sentinelflow.local/i);
    const orgInput = screen.getByPlaceholderText(/CyberDefense Operations/i);
    const passInputs = screen.getAllByPlaceholderText(/••••••••••••/i);

    fireEvent.change(nameInput, { target: { value: 'Sarah Chen' } });
    fireEvent.change(emailInput, { target: { value: 'sarah.chen@sentinelflow.local' } });
    fireEvent.change(orgInput, { target: { value: 'CyberDefense SOC' } });
    fireEvent.change(passInputs[0], { target: { value: 'SecurePass@2026' } });
    fireEvent.change(passInputs[1], { target: { value: 'SecurePass@2026' } });

    const submitBtn = screen.getByRole('button', { name: /Register Organization & Admin/i });
    fireEvent.click(submitBtn);

    expect(await screen.findByText(/An account with this email address already exists/i)).toBeInTheDocument();
  });
});
