import { useState } from 'react';
import {
  ShieldAlert,
  Radio,
  Database,
  Workflow,
  LogOut,
  Building2,
  ChevronDown,
  Check,
  RefreshCw,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import type { SystemHealthResponse, OrgRole } from '@sentinelflow/shared';

interface NavbarProps {
  health: SystemHealthResponse | null;
  onRefresh: () => void;
  isLoading: boolean;
}

export function Navbar({ health, onRefresh, isLoading }: NavbarProps) {
  const { user, activeOrganization, activeRole, logout, switchOrganization } = useAuth();
  const [isOrgDropdownOpen, setIsOrgDropdownOpen] = useState(false);

  const getRoleBadge = (role: OrgRole | null) => {
    switch (role) {
      case 'ADMIN':
        return 'bg-purple-950 text-purple-300 border-purple-800';
      case 'ANALYST':
        return 'bg-emerald-950 text-emerald-300 border-emerald-800';
      case 'VIEWER':
      default:
        return 'bg-sky-950 text-sky-300 border-sky-800';
    }
  };

  return (
    <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50 px-6 py-3 flex items-center justify-between">
      {/* Brand & Title */}
      <div className="flex items-center space-x-3">
        <div className="p-2 bg-emerald-500/10 rounded-lg border border-emerald-500/20 text-emerald-400">
          <ShieldAlert className="w-6 h-6 text-emerald-400" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <span className="font-bold text-lg tracking-wide text-white">SentinelFlow</span>
            <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 font-mono font-medium">
              SOC Platform
            </span>
          </div>
          <p className="text-xs text-slate-400">Enterprise AI Security Operations</p>
        </div>
      </div>

      {/* Center / Right: Health, Organization Switcher & User Profile */}
      <div className="flex items-center space-x-4 text-xs">
        {/* System Health Badges */}
        <div className="hidden lg:flex items-center space-x-3 font-mono">
          <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded bg-slate-800/80 border border-slate-700">
            <Radio className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
            <span className="text-slate-400">API:</span>
            <span className="text-emerald-400 font-semibold">{health?.services.api || 'Ready'}</span>
          </div>
          <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded bg-slate-800/80 border border-slate-700">
            <Database className="w-3.5 h-3.5 text-sky-400" />
            <span className="text-slate-400">DB:</span>
            <span className="text-sky-400 font-semibold">{health?.services.database || 'Connected'}</span>
          </div>
          <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded bg-slate-800/80 border border-slate-700">
            <Workflow className="w-3.5 h-3.5 text-purple-400" />
            <span className="text-slate-400">n8n:</span>
            <span
              className={`font-semibold capitalize ${
                health?.services.n8n === 'reachable' || health?.services.n8n === 'connected'
                  ? 'text-emerald-400'
                  : health?.services.n8n === 'configured'
                  ? 'text-amber-400'
                  : health?.services.n8n === 'unreachable'
                  ? 'text-rose-400'
                  : 'text-slate-400'
              }`}
            >
              {health?.services.n8n || 'Configured'}
            </span>
          </div>
        </div>

        {/* Server-Verified Organization Switcher */}
        <div className="relative">
          <button
            onClick={() => setIsOrgDropdownOpen(!isOrgDropdownOpen)}
            className="flex items-center space-x-2 px-3 py-1.5 bg-slate-850 hover:bg-slate-800 border border-slate-700 rounded-lg text-slate-200 transition font-sans"
            title="Switch Active Organization (Server-Verified)"
          >
            <Building2 className="w-3.5 h-3.5 text-emerald-400" />
            <span className="font-semibold max-w-[130px] truncate">
              {activeOrganization?.organizationName || 'Select Org'}
            </span>
            <ChevronDown className="w-3 h-3 text-slate-400" />
          </button>

          {isOrgDropdownOpen && user && (
            <div className="absolute right-0 mt-2 w-64 bg-slate-900 border border-slate-800 rounded-xl shadow-2xl p-2 z-50 space-y-1">
              <div className="px-3 py-1.5 text-[10px] font-bold uppercase tracking-wider text-slate-400 border-b border-slate-800">
                Authorized Organizations
              </div>
              {user.memberships.map((membership) => (
                <button
                  key={membership.organizationId}
                  onClick={() => {
                    switchOrganization(membership.organizationId);
                    setIsOrgDropdownOpen(false);
                  }}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-left text-xs transition ${
                    activeOrganization?.organizationId === membership.organizationId
                      ? 'bg-emerald-500/10 text-emerald-300 font-semibold border border-emerald-500/20'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <div className="truncate">
                    <div>{membership.organizationName}</div>
                    <div className="text-[10px] text-slate-500 font-mono">Role: {membership.role}</div>
                  </div>
                  {activeOrganization?.organizationId === membership.organizationId && (
                    <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0 ml-2" />
                  )}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Current User & Role Badge */}
        <div className="flex items-center space-x-2.5 pl-2 border-l border-slate-800">
          <div className="hidden sm:block text-right">
            <div className="font-semibold text-white truncate max-w-[120px]">{user?.name}</div>
            <div className="text-[10px] text-slate-400 truncate max-w-[120px]">{user?.email}</div>
          </div>
          <span
            className={`px-2 py-0.5 rounded border text-[11px] font-mono font-bold tracking-wide uppercase ${getRoleBadge(
              activeRole,
            )}`}
          >
            {activeRole || 'USER'}
          </span>
        </div>

        {/* Refresh & Logout Buttons */}
        <button
          onClick={onRefresh}
          disabled={isLoading}
          className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700 transition"
          title="Refresh Data"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
        </button>

        <button
          onClick={logout}
          className="flex items-center space-x-1 px-2.5 py-1.5 bg-rose-950/40 hover:bg-rose-900/60 border border-rose-800/60 text-rose-300 rounded-lg text-xs font-semibold transition"
          title="Sign Out"
        >
          <LogOut className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">Logout</span>
        </button>
      </div>
    </header>
  );
}
