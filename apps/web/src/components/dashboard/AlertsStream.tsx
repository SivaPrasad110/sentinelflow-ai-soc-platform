import { useState, type FormEvent } from 'react';
import { Activity, Plus, ShieldCheck, Lock } from 'lucide-react';
import type { SecurityAlert, AlertSeverity } from '@sentinelflow/shared';
import { useAuth } from '../../context/AuthContext';

interface AlertsStreamProps {
  alerts: SecurityAlert[];
  isLoading: boolean;
  error: string | null;
  onRefresh: () => void;
  onIngestAlert: (data: {
    title: string;
    description: string;
    severity: AlertSeverity;
    source: string;
  }) => Promise<void>;
}

export function AlertsStream({
  alerts,
  isLoading,
  error,
  onRefresh,
  onIngestAlert,
}: AlertsStreamProps) {
  const { activeRole } = useAuth();
  const [isIngestOpen, setIsIngestOpen] = useState(false);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<AlertSeverity>('HIGH');
  const [source, setSource] = useState('CrowdStrike EDR');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const canIngest = activeRole === 'ANALYST' || activeRole === 'ADMIN';

  const getSeverityBadge = (sev: AlertSeverity) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-950 text-red-400 border border-red-800';
      case 'HIGH':
        return 'bg-orange-950 text-orange-400 border border-orange-800';
      case 'MEDIUM':
        return 'bg-amber-950 text-amber-400 border border-amber-800';
      default:
        return 'bg-emerald-950 text-emerald-400 border border-emerald-800';
    }
  };

  const handleIngestSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!title.trim() || !description.trim()) return;

    setIsSubmitting(true);
    try {
      await onIngestAlert({
        title: title.trim(),
        description: description.trim(),
        severity,
        source: source.trim(),
      });
      setTitle('');
      setDescription('');
      setIsIngestOpen(false);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-base font-bold text-white flex items-center space-x-2">
            <Activity className="w-5 h-5 text-amber-400" />
            <span>Ingested Security Alerts Stream</span>
          </h3>
          <p className="text-xs text-slate-400">
            Raw telemetry streams filtered to your authorized organization.
          </p>
        </div>

        {canIngest ? (
          <button
            onClick={() => setIsIngestOpen(!isIngestOpen)}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-xs font-semibold transition"
          >
            <Plus className="w-4 h-4" />
            <span>Ingest Alert</span>
          </button>
        ) : (
          <div
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800/80 text-slate-500 border border-slate-700/60 rounded-lg text-xs cursor-not-allowed"
            title="Viewer Role: Read-only access"
          >
            <Lock className="w-3.5 h-3.5" />
            <span>Ingest (Viewer: Read-only)</span>
          </div>
        )}
      </div>

      {isIngestOpen && canIngest && (
        <form onSubmit={handleIngestSubmit} className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-3 text-xs">
          <div className="font-semibold text-amber-400">Manual Alert Ingestion</div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label className="block text-slate-400 uppercase font-semibold mb-1">Alert Title</label>
              <input
                type="text"
                required
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="e.g. AWS GuardDuty Unauthorized Access"
                className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-slate-200"
              />
            </div>
            <div>
              <label className="block text-slate-400 uppercase font-semibold mb-1">Telemetry Source</label>
              <input
                type="text"
                required
                value={source}
                onChange={(e) => setSource(e.target.value)}
                placeholder="e.g. CrowdStrike EDR / Palo Alto WAF"
                className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-slate-200"
              />
            </div>
          </div>
          <div>
            <label className="block text-slate-400 uppercase font-semibold mb-1">Description</label>
            <input
              type="text"
              required
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Telemetry details, host IP, user identity..."
              className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-slate-200"
            />
          </div>
          <div className="flex items-center justify-between pt-2">
            <div>
              <label className="inline text-slate-400 uppercase font-semibold mr-2">Severity:</label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as AlertSeverity)}
                className="px-2 py-1 bg-slate-900 border border-slate-800 rounded text-slate-200"
              >
                <option value="LOW">LOW</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="HIGH">HIGH</option>
                <option value="CRITICAL">CRITICAL</option>
              </select>
            </div>
            <div className="flex space-x-2">
              <button
                type="button"
                onClick={() => setIsIngestOpen(false)}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 rounded text-slate-300"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSubmitting}
                className="px-3 py-1.5 bg-amber-600 hover:bg-amber-500 rounded text-white font-semibold"
              >
                {isSubmitting ? 'Ingesting...' : 'Submit Alert'}
              </button>
            </div>
          </div>
        </form>
      )}

      {error && (
        <div className="p-4 bg-rose-950/30 border border-rose-800 rounded-xl text-xs text-rose-300 flex items-center justify-between">
          <span>{error}</span>
          <button onClick={onRefresh} className="px-2 py-1 bg-rose-900/60 rounded text-white font-semibold">
            Retry
          </button>
        </div>
      )}

      {isLoading ? (
        <div className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="p-4 bg-slate-950/40 border border-slate-800 rounded-lg animate-pulse h-16" />
          ))}
        </div>
      ) : alerts.length === 0 ? (
        <div className="p-8 text-center text-slate-500 border border-slate-800 rounded-lg space-y-1">
          <ShieldCheck className="w-6 h-6 mx-auto text-emerald-500" />
          <p className="text-xs text-slate-400 font-semibold">No active alerts</p>
          <p className="text-[11px]">No security alerts recorded for this organization.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {alerts.map((alert) => (
            <div
              key={alert.id}
              className="p-4 bg-slate-950/60 border border-slate-800 rounded-lg flex items-center justify-between"
            >
              <div>
                <div className="flex items-center space-x-2 mb-1">
                  <span className="text-xs font-mono text-slate-400">{alert.id}</span>
                  <span className="text-xs font-mono text-slate-500">• {alert.source}</span>
                  <span
                    className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold ${getSeverityBadge(
                      alert.severity,
                    )}`}
                  >
                    {alert.severity}
                  </span>
                </div>
                <h4 className="text-sm font-semibold text-white">{alert.title}</h4>
                <p className="text-xs text-slate-400 mt-0.5">{alert.description}</p>
              </div>
              <span className="text-xs text-slate-400 font-mono">
                {new Date(alert.detectedAt).toLocaleTimeString()}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
