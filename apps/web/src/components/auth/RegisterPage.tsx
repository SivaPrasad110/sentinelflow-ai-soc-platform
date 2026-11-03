import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Lock,
  Mail,
  User,
  Building2,
  AlertCircle,
  ArrowRight,
  Eye,
  EyeOff,
  Check,
  X,
  BadgeCheck,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

interface RegisterPageProps {
  onNavigateToLogin?: () => void;
}

export function RegisterPage({ onNavigateToLogin }: RegisterPageProps) {
  const { register, isLoading, authError, clearError } = useAuth();

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [organizationName, setOrganizationName] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  // Password complexity checks matching backend DTO
  const passwordRules = [
    { id: 'length', label: 'At least 10 characters', met: password.length >= 10 },
    { id: 'uppercase', label: 'One uppercase letter (A-Z)', met: /[A-Z]/.test(password) },
    { id: 'lowercase', label: 'One lowercase letter (a-z)', met: /[a-z]/.test(password) },
    { id: 'number', label: 'One number (0-9)', met: /[0-9]/.test(password) },
    { id: 'special', label: 'One special character (!@#$%^&*)', met: /[^A-Za-z0-9]/.test(password) },
  ];

  const isPasswordComplex = passwordRules.every((rule) => rule.met);
  const passwordsMatch = password.length > 0 && password === confirmPassword;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    clearError();
    setLocalError(null);

    if (!name.trim()) {
      setLocalError('Please enter your full name.');
      return;
    }

    if (!email.trim()) {
      setLocalError('Please enter your corporate email address.');
      return;
    }

    if (!organizationName.trim()) {
      setLocalError('Please enter your organization or SOC name.');
      return;
    }

    if (!isPasswordComplex) {
      setLocalError('Password does not satisfy all security complexity criteria.');
      return;
    }

    if (password !== confirmPassword) {
      setLocalError('Passwords do not match. Please verify your confirmation password.');
      return;
    }

    try {
      if (register) {
        await register({
          name: name.trim(),
          email: email.trim().toLowerCase(),
          password,
          organizationName: organizationName.trim(),
        });
      }
    } catch {
      // Error handled by AuthContext state (authError)
    }
  };

  const displayedError = localError || authError;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col justify-center items-center p-4 sm:p-6 selection:bg-emerald-500/30">
      {/* Subtle Background Glow */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-emerald-500/5 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-lg space-y-6 relative z-10">
        {/* Header Logo */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center justify-center p-3 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 mb-2 shadow-lg shadow-emerald-950/20">
            <ShieldAlert className="w-8 h-8 text-emerald-400" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center justify-center space-x-2">
            <span>SentinelFlow</span>
            <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 font-mono font-medium">
              SOC ONBOARDING
            </span>
          </h1>
          <p className="text-xs text-slate-400 max-w-sm mx-auto">
            Create a dedicated tenant boundary for your Security Operations Center. The initial account is securely provisioned with Tenant Administrator privileges.
          </p>
        </div>

        {/* Registration Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-8 shadow-2xl space-y-6 backdrop-blur">
          {displayedError && (
            <div className="p-3.5 bg-rose-950/40 border border-rose-800/80 rounded-xl flex items-start space-x-3 text-xs text-rose-200">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div className="flex-1">
                <span className="font-semibold">Registration Notice:</span> {displayedError}
              </div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Full Name */}
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                Full Name
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                  <User className="w-4 h-4" />
                </div>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => {
                    clearError();
                    setLocalError(null);
                    setName(e.target.value);
                  }}
                  placeholder="Sarah Chen"
                  className="w-full pl-10 pr-4 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition"
                />
              </div>
            </div>

            {/* Corporate Email */}
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
                    setLocalError(null);
                    setEmail(e.target.value);
                  }}
                  placeholder="analyst@sentinelflow.local"
                  className="w-full pl-10 pr-4 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition"
                />
              </div>
            </div>

            {/* Organization Name */}
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                Organization / SOC Name
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                  <Building2 className="w-4 h-4" />
                </div>
                <input
                  type="text"
                  required
                  value={organizationName}
                  onChange={(e) => {
                    clearError();
                    setLocalError(null);
                    setOrganizationName(e.target.value);
                  }}
                  placeholder="CyberDefense Operations"
                  className="w-full pl-10 pr-4 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition"
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                Master Password
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={password}
                  onChange={(e) => {
                    clearError();
                    setLocalError(null);
                    setPassword(e.target.value);
                  }}
                  placeholder="••••••••••••"
                  className="w-full pl-10 pr-10 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition font-mono"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-slate-500 hover:text-slate-300 transition"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>

              {/* Real-time Password Complexity Rules */}
              <div className="mt-2.5 p-2.5 bg-slate-950/70 border border-slate-800/80 rounded-lg space-y-1">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 mb-1">
                  Security Complexity Requirements
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-1 text-[11px]">
                  {passwordRules.map((rule) => (
                    <div
                      key={rule.id}
                      className={`flex items-center space-x-1.5 transition-colors ${
                        rule.met ? 'text-emerald-400' : 'text-slate-500'
                      }`}
                    >
                      {rule.met ? (
                        <Check className="w-3 h-3 text-emerald-400 shrink-0" />
                      ) : (
                        <div className="w-3 h-3 rounded-full border border-slate-600 shrink-0" />
                      )}
                      <span>{rule.label}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Confirm Password */}
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                Confirm Password
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  type={showConfirmPassword ? 'text' : 'password'}
                  required
                  value={confirmPassword}
                  onChange={(e) => {
                    clearError();
                    setLocalError(null);
                    setConfirmPassword(e.target.value);
                  }}
                  placeholder="••••••••••••"
                  className="w-full pl-10 pr-10 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition font-mono"
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  aria-label={showConfirmPassword ? 'Hide confirm password' : 'Show confirm password'}
                  className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-slate-500 hover:text-slate-300 transition"
                >
                  {showConfirmPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {confirmPassword.length > 0 && (
                <div className="mt-1 text-[11px] flex items-center space-x-1">
                  {passwordsMatch ? (
                    <span className="text-emerald-400 flex items-center space-x-1">
                      <Check className="w-3 h-3" />
                      <span>Passwords match</span>
                    </span>
                  ) : (
                    <span className="text-rose-400 flex items-center space-x-1">
                      <X className="w-3 h-3" />
                      <span>Passwords do not match</span>
                    </span>
                  )}
                </div>
              )}
            </div>

            {/* Role Notice (Governed by backend authorization) */}
            <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-xl flex items-center space-x-2.5 text-xs text-slate-400">
              <BadgeCheck className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>
                <strong className="text-slate-200">Role Notice:</strong> Initial onboarding account is provisioned as an{' '}
                <strong className="text-emerald-400">Organization Admin</strong>. Further roles (Analysts, Viewers) are granted via invitation.
              </span>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isLoading || !isPasswordComplex || !passwordsMatch}
              className="w-full py-2.5 px-4 bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-800 disabled:text-slate-500 disabled:cursor-not-allowed text-white rounded-xl text-sm font-semibold flex items-center justify-center space-x-2 transition shadow-lg shadow-emerald-950/40"
            >
              {isLoading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                  <span>Provisioning SOC Tenant...</span>
                </>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4" />
                  <span>Register Organization & Admin</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Navigation to Login */}
          {onNavigateToLogin && (
            <div className="pt-4 border-t border-slate-800/80 text-center">
              <p className="text-xs text-slate-400">
                Already registered with an organization?{' '}
                <button
                  type="button"
                  onClick={onNavigateToLogin}
                  className="text-emerald-400 hover:text-emerald-300 font-semibold hover:underline underline-offset-4 transition"
                >
                  Sign in to SOC
                </button>
              </p>
            </div>
          )}
        </div>

        {/* Security Notice */}
        <div className="text-center text-[11px] text-slate-500 flex items-center justify-center space-x-1.5">
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-500" />
          <span>Argon2id Salted Hashing • Tenant Boundary Isolation • Automatic Session Establishment</span>
        </div>
      </div>
    </div>
  );
}
