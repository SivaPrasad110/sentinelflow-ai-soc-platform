import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import type { UserProfile, OrganizationMembership, OrgRole } from '@sentinelflow/shared';
import {
  setAccessToken,
  setActiveOrganizationId,
  setSessionExpiredHandler,
  secureFetch,
  buildApiUrl,
} from '../services/api';

export interface AuthContextType {
  user: UserProfile | null;
  activeOrganization: OrganizationMembership | null;
  activeRole: OrgRole | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  authError: string | null;
  login: (credentials: { email: string; password: string; organizationIdHint?: string }) => Promise<void>;
  register?: (data: { email: string; password: string; name: string; organizationName: string }) => Promise<void>;
  logout: () => Promise<void>;
  switchOrganization: (organizationId: string) => Promise<void>;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [activeOrganization, setActiveOrganization] = useState<OrganizationMembership | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [authError, setAuthError] = useState<string | null>(null);

  const handleSessionExpired = useCallback(() => {
    setAccessToken(null);
    setActiveOrganizationId(null);
    setUser(null);
    setActiveOrganization(null);
    setAuthError('Your session has expired. Please sign in again.');
  }, []);

  useEffect(() => {
    setSessionExpiredHandler(handleSessionExpired);
  }, [handleSessionExpired]);

  // Attempt to restore session on initial load via secure HTTP-only refresh cookie
  useEffect(() => {
    async function restoreSession() {
      setIsLoading(true);
      try {
        const refreshRes = await fetch(buildApiUrl('/api/v1/auth/refresh'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
        });

        if (refreshRes.ok) {
          const { accessToken } = await refreshRes.json();
          setAccessToken(accessToken);

          const meRes = await secureFetch('/api/v1/auth/me');
          if (meRes.ok) {
            const profile: UserProfile = await meRes.json();
            setUser(profile);
            const activeOrg =
              profile.memberships.find((m) => m.organizationId === profile.activeOrganizationId) ||
              profile.memberships[0] ||
              null;
            setActiveOrganization(activeOrg);
            if (activeOrg) {
              setActiveOrganizationId(activeOrg.organizationId);
            }
          }
        }
      } catch {
        // No existing session or server unavailable
        handleSessionExpired();
      } finally {
        setIsLoading(false);
      }
    }

    restoreSession();
  }, [handleSessionExpired]);

  const login = async ({
    email,
    password,
    organizationIdHint,
  }: {
    email: string;
    password: string;
    organizationIdHint?: string;
  }) => {
    setIsLoading(true);
    setAuthError(null);

    try {
      const res = await fetch(buildApiUrl('/api/v1/auth/login'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email, password, organizationIdHint }),
      });

      if (!res.ok) {
        let errorMsg = 'Invalid email or password.';
        if (res.status === 429) {
          errorMsg = 'Rate limit exceeded: too many failed login attempts. Please wait 1 minute.';
        } else {
          try {
            const errData = await res.json();
            if (errData.message) {
              errorMsg = Array.isArray(errData.message) ? errData.message.join(', ') : errData.message;
            }
          } catch {
            // fallback
          }
        }
        throw new Error(errorMsg);
      }

      const data = await res.json();
      setAccessToken(data.accessToken);
      setUser(data.user);

      const activeOrg =
        data.user.memberships.find((m: OrganizationMembership) => m.organizationId === data.user.activeOrganizationId) ||
        data.user.memberships[0] ||
        null;

      setActiveOrganization(activeOrg);
      if (activeOrg) {
        setActiveOrganizationId(activeOrg.organizationId);
      }
    } catch (err: any) {
      const message =
        err.name === 'TypeError' || err.message === 'Failed to fetch'
          ? 'Unable to connect to SentinelFlow API. Please verify network connectivity.'
          : err.message || 'Authentication failed.';
      setAuthError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (data: {
    email: string;
    password: string;
    name: string;
    organizationName: string;
  }) => {
    setIsLoading(true);
    setAuthError(null);

    try {
      const res = await fetch(buildApiUrl('/api/v1/auth/register'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(data),
      });

      if (!res.ok) {
        let errorMsg = 'Registration failed.';
        if (res.status === 409) {
          errorMsg = 'An account with this corporate email or organization already exists.';
        }
        try {
          const errData = await res.json();
          if (errData.message) {
            errorMsg = Array.isArray(errData.message) ? errData.message.join(', ') : errData.message;
          }
        } catch {
          // fallback
        }
        throw new Error(errorMsg);
      }

      const resData = await res.json();
      setAccessToken(resData.accessToken);
      setUser(resData.user);

      const activeOrg =
        resData.user.memberships?.find((m: OrganizationMembership) => m.organizationId === resData.user.activeOrganizationId) ||
        resData.user.memberships?.[0] ||
        null;

      setActiveOrganization(activeOrg);
      if (activeOrg) {
        setActiveOrganizationId(activeOrg.organizationId);
      }
    } catch (err: any) {
      const message =
        err.name === 'TypeError' || err.message === 'Failed to fetch'
          ? 'Unable to connect to SentinelFlow API. Please verify network connectivity.'
          : err.message || 'Registration failed.';
      setAuthError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async () => {
    try {
      await fetch(buildApiUrl('/api/v1/auth/logout'), {
        method: 'POST',
        credentials: 'include',
      });
    } catch {
      // ignore network errors on logout
    } finally {
      handleSessionExpired();
    }
  };

  const switchOrganization = async (targetOrgId: string) => {
    if (!user) return;

    const targetMembership = user.memberships.find((m) => m.organizationId === targetOrgId);
    if (!targetMembership) {
      setAuthError(`You are not an authorized member of organization "${targetOrgId}".`);
      return;
    }

    // Set organization header hint and refresh active role from server
    setActiveOrganizationId(targetOrgId);

    try {
      const res = await secureFetch('/api/v1/auth/me', {
        headers: { 'x-organization-id': targetOrgId },
      });

      if (res.ok) {
        const updatedProfile: UserProfile = await res.json();
        setUser(updatedProfile);
        const resolvedOrg =
          updatedProfile.memberships.find((m) => m.organizationId === targetOrgId) || targetMembership;
        setActiveOrganization(resolvedOrg);
      } else {
        setActiveOrganization(targetMembership);
      }
    } catch {
      setActiveOrganization(targetMembership);
    }
  };

  const clearError = () => setAuthError(null);

  const activeRole: OrgRole | null = activeOrganization?.role || user?.activeRole || null;

  return (
    <AuthContext.Provider
      value={{
        user,
        activeOrganization,
        activeRole,
        isAuthenticated: !!user && !!activeOrganization,
        isLoading,
        authError,
        login,
        register,
        logout,
        switchOrganization,
        clearError,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
