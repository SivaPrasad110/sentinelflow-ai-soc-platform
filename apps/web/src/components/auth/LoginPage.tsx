import React, { useState } from 'react';
import {
  ShieldAlert,
  Lock,
  Mail,
  KeyRound,
  AlertCircle,
  ArrowRight,
  ShieldCheck,
  Building2,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

export function LoginPage() {
  const { login, isLoading, authError, clearError } = useAuth();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [orgHint, setOrgHint] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) return;

    try {
      await login({
        email,
        password,
        organizationIdHint: orgHint.trim() || undefined,
      });
    } catch {
      // Error handled by AuthContext state
    }
  };

  const handleQuickFill = (demoEmail: string, demoPass: string, demoOrg?: string) => {
    clearError();
    setEmail(demoEmail);
    setPassword(demoPass);
    if (demoOrg) setOrgHint(demoOrg);
    else setOrgHint('');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col justify-center items-center p-4 sm:p-6 selection:bg-emerald-500/30">
      {/* Background Glow */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-emerald-500/5 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-md space-y-6 relative z-10">
        {/* Header Logo */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center justify-center p-3 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 mb-2 shadow-lg shadow-emerald-950/20">
            <ShieldAlert className="w-8 h-8 text-emerald-400" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center justify-center space-x-2">
            <span>SentinelFlow</span>
            <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 font-mono font-medium">
              SOC
            </span>
          </h1>
          <p className="text-xs text-slate-400 max-w-sm mx-auto">
            Production-oriented AI Security Operations Platform. Authenticate to access real-time telemetry, triage queue, and automated playbooks.
          </p>
        </div>

        {/* Login Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-8 shadow-2xl space-y-6 backdrop-blur">
          {authError && (
            <div className="p-3.5 bg-rose-950/40 border border-rose-800/80 rounded-xl flex items-start space-x-3 text-xs text-rose-200">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div className="flex-1">
                <span className="font-semibold">Authentication Notice:</span> {authError}
              </div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                Corporate Email
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                  <Mail className="w-4 h-4" />
                </div>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => {
                    clearError();
                    setEmail(e.target.value);
                  }}
                  placeholder="analyst@sentinelflow.local"
                  className="w-full pl-10 pr-4 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                Password
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => {
                    clearError();
                    setPassword(e.target.value);
                  }}
                  placeholder="••••••••••••"
                  className="w-full pl-10 pr-4 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5 flex items-center justify-between">
                <span>Organization Identifier</span>
                <span className="text-[10px] text-slate-500 lowercase font-normal">(Optional selection hint)</span>
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                  <Building2 className="w-4 h-4" />
                </div>
                <input
                  type="text"
                  value={orgHint}
                  onChange={(e) => {
                    clearError();
                    setOrgHint(e.target.value);
                  }}
                  placeholder="e.g. org-cyberdefense-001"
                  className="w-full pl-10 pr-4 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500 transition font-mono"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full py-2.5 px-4 bg-emerald-600 hover:bg-emerald-500 disabled:bg-emerald-800 text-white rounded-xl text-sm font-semibold flex items-center justify-center space-x-2 transition shadow-lg shadow-emerald-950/40"
            >
              {isLoading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                  <span>Verifying Credentials...</span>
                </>
              ) : (
                <>
                  <KeyRound className="w-4 h-4" />
                  <span>Authenticate to SOC</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Quick-fill Dev Accounts for local evaluation */}
          <div className="pt-4 border-t border-slate-800/80 space-y-2.5">
            <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider text-center">
              Quick Test Accounts (Seeded Roles)
            </p>
            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => handleQuickFill('sarah.chen@sentinelflow.local', 'AnalystPassword123!', 'org-cyberdefense-001')}
                className="px-2 py-1.5 bg-slate-800/60 hover:bg-slate-800 border border-slate-700/60 hover:border-emerald-500/50 rounded-lg text-left transition"
              >
                <div className="text-[10px] font-bold text-emerald-400">Analyst</div>
                <div className="text-[9px] text-slate-400 truncate">Sarah Chen</div>
              </button>

              <button
                type="button"
                onClick={() => handleQuickFill('viewer@sentinelflow.local', 'ViewerPassword123!', 'org-cyberdefense-001')}
                className="px-2 py-1.5 bg-slate-800/60 hover:bg-slate-800 border border-slate-700/60 hover:border-sky-500/50 rounded-lg text-left transition"
              >
                <div className="text-[10px] font-bold text-sky-400">Viewer</div>
                <div className="text-[9px] text-slate-400 truncate">Read-Only</div>
              </button>

              <button
                type="button"
                onClick={() => handleQuickFill('admin@sentinelflow.local', 'AdminPassword123!', 'org-cyberdefense-001')}
                className="px-2 py-1.5 bg-slate-800/60 hover:bg-slate-800 border border-slate-700/60 hover:border-purple-500/50 rounded-lg text-left transition"
              >
                <div className="text-[10px] font-bold text-purple-400">Admin</div>
                <div className="text-[9px] text-slate-400 truncate">Full Access</div>
              </button>
            </div>
          </div>
        </div>

        {/* Security Notice */}
        <div className="text-center text-[11px] text-slate-500 flex items-center justify-center space-x-1.5">
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-500" />
          <span>Argon2id Hashing • 15m JWT Session • Anti-Brute Force Protection</span>
        </div>
      </div>
    </div>
  );
}
