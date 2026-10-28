import { useState } from 'react';
import {
  ShieldAlert,
  Plus,
  Trash2,
  Terminal,
  Cpu,
  AlertTriangle,
  Lock,
} from 'lucide-react';
import type { Incident, AlertSeverity } from '@sentinelflow/shared';
import { useAuth } from '../../context/AuthContext';
import { CreateIncidentModal } from './CreateIncidentModal';

interface IncidentsQueueProps {
  incidents: Incident[];
  isLoading: boolean;
  error: string | null;
  onRefresh: () => void;
  onCreateIncident: (data: any) => Promise<void>;
  onDeleteIncident: (id: string) => Promise<void>;
  selectedIncident: Incident | null;
  onSelectIncident: (inc: Incident) => void;
}

export function IncidentsQueue({
  incidents,
  isLoading,
  error,
  onRefresh,
  onCreateIncident,
  onDeleteIncident,
  selectedIncident,
  onSelectIncident,
}: IncidentsQueueProps) {
  const { activeRole } = useAuth();
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const canCreate = activeRole === 'ANALYST' || activeRole === 'ADMIN';
  const canDelete = activeRole === 'ADMIN';

  const getSeverityBadge = (severity: AlertSeverity) => {
    switch (severity) {
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

  const handleCreateSubmit = async (data: any) => {
    setIsSubmitting(true);
    try {
      await onCreateIncident(data);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Top Action Bar */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-bold text-white flex items-center space-x-2">
            <ShieldAlert className="w-5 h-5 text-emerald-400" />
            <span>Active Incident Queue</span>
          </h2>
          <p className="text-xs text-slate-400">
            Real-time security incidents persisted in PostgreSQL for the active organization.
          </p>
        </div>

        {canCreate ? (
          <button
            onClick={() => setIsCreateModalOpen(true)}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold transition shadow-md shadow-emerald-950/30"
          >
            <Plus className="w-4 h-4" />
            <span>Create Incident</span>
          </button>
        ) : (
          <div
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800/80 text-slate-500 border border-slate-700/60 rounded-lg text-xs cursor-not-allowed"
            title="Read-only access (Viewer Role)"
          >
            <Lock className="w-3.5 h-3.5" />
            <span>Create (Viewer: Read-only)</span>
          </div>
        )}
      </div>

      {/* Error Banner */}
      {error && (
        <div className="p-4 bg-rose-950/30 border border-rose-800 rounded-xl text-xs text-rose-300 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
          <button
            onClick={onRefresh}
            className="px-2.5 py-1 bg-rose-900/60 hover:bg-rose-900 rounded font-semibold text-white transition"
          >
            Retry
          </button>
        </div>
      )}

      {/* Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left List: Incident Items */}
        <div className="lg:col-span-1 space-y-3">
          {isLoading ? (
            // Skeleton loaders
            Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-2 animate-pulse">
                <div className="h-4 bg-slate-800 rounded w-1/3" />
                <div className="h-4 bg-slate-800 rounded w-3/4" />
                <div className="h-3 bg-slate-800 rounded w-1/2" />
              </div>
            ))
          ) : incidents.length === 0 ? (
            <div className="p-8 text-center bg-slate-900/40 border border-slate-800 rounded-xl space-y-2">
              <ShieldAlert className="w-8 h-8 text-slate-600 mx-auto" />
              <p className="text-xs text-slate-400 font-semibold">No active incidents found</p>
              <p className="text-[11px] text-slate-500">
                The threat perimeter for this organization is currently clear.
              </p>
            </div>
          ) : (
            incidents.map((incident) => (
              <div
                key={incident.id}
                onClick={() => onSelectIncident(incident)}
                className={`p-4 rounded-xl border cursor-pointer transition ${
                  selectedIncident?.id === incident.id
                    ? 'bg-slate-850 border-emerald-500/60 shadow-lg shadow-emerald-950/20'
                    : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-xs font-mono font-semibold text-slate-400 truncate max-w-[120px]">
                    {incident.id}
                  </span>
                  <span
                    className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold ${getSeverityBadge(
                      incident.severity,
                    )}`}
                  >
                    {incident.severity}
                  </span>
                </div>
                <h4 className="text-sm font-semibold text-white line-clamp-1">{incident.title}</h4>
                <p className="text-xs text-slate-400 line-clamp-2 mt-1">{incident.description}</p>
                <div className="mt-3 pt-2.5 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400 font-mono">
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    {incident.status}
                  </span>
                  <span>{incident.iocs?.length || 0} IOCs</span>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Right Detail Card */}
        <div className="lg:col-span-2">
          {selectedIncident ? (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
              {/* Incident Header */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-mono bg-slate-800 px-2.5 py-1 rounded text-slate-300">
                      {selectedIncident.id}
                    </span>
                    <span
                      className={`text-xs px-2.5 py-1 rounded font-mono font-bold ${getSeverityBadge(
                        selectedIncident.severity,
                      )}`}
                    >
                      {selectedIncident.severity}
                    </span>
                    <span className="text-xs px-2.5 py-1 rounded bg-sky-950 text-sky-400 border border-sky-800 font-mono">
                      {selectedIncident.status}
                    </span>
                  </div>

                  {canDelete && (
                    <button
                      onClick={() => onDeleteIncident(selectedIncident.id)}
                      className="p-1.5 rounded-lg text-rose-400 hover:text-rose-300 hover:bg-rose-950/40 border border-rose-900/50 transition"
                      title="Delete Incident (Admin Only)"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </div>
                <h3 className="text-xl font-bold text-white mt-1">{selectedIncident.title}</h3>
                <p className="text-xs text-slate-300 mt-2 leading-relaxed">{selectedIncident.description}</p>
              </div>

              {/* AI Analysis Section */}
              {selectedIncident.aiAnalysis && (
                <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/30 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2 text-emerald-400 font-semibold text-xs">
                      <Cpu className="w-4 h-4" />
                      <span>AI Triage & Impact Assessment</span>
                    </div>
                    <span className="text-[11px] text-emerald-300 font-mono">
                      Confidence: {(selectedIncident.aiAnalysis.confidenceScore * 100).toFixed(0)}%
                    </span>
                  </div>
                  <p className="text-xs text-slate-200 leading-relaxed">
                    {selectedIncident.aiAnalysis.summary}
                  </p>
                  <div className="text-xs bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
                    <span className="text-rose-400 font-semibold">Risk: </span>
                    <span className="text-slate-300">{selectedIncident.aiAnalysis.riskAssessment}</span>
                  </div>
                  {selectedIncident.aiAnalysis.recommendedMitigations?.length > 0 && (
                    <div className="space-y-1">
                      <p className="text-[11px] font-semibold text-emerald-300 uppercase tracking-wide">
                        Remediation Actions:
                      </p>
                      <ul className="text-xs text-slate-300 space-y-1 list-disc list-inside">
                        {selectedIncident.aiAnalysis.recommendedMitigations.map((step, idx) => (
                          <li key={idx}>{step}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {/* IOCs Table */}
              <div>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2 flex items-center space-x-1.5">
                  <Terminal className="w-4 h-4 text-sky-400" />
                  <span>Indicators of Compromise ({selectedIncident.iocs?.length || 0})</span>
                </h4>
                {selectedIncident.iocs && selectedIncident.iocs.length > 0 ? (
                  <div className="overflow-x-auto border border-slate-800 rounded-lg">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-slate-800/80 text-slate-400 font-mono">
                        <tr>
                          <th className="p-2.5">Type</th>
                          <th className="p-2.5">Indicator Value</th>
                          <th className="p-2.5">Threat Score</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800 font-mono">
                        {selectedIncident.iocs.map((ioc) => (
                          <tr key={ioc.id} className="hover:bg-slate-800/40">
                            <td className="p-2.5 text-sky-400">{ioc.type}</td>
                            <td className="p-2.5 text-slate-200 select-all">{ioc.value}</td>
                            <td className="p-2.5">
                              <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-400 font-bold">
                                {ioc.threatScore || 'N/A'}/100
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="text-xs text-slate-500 italic">No IOCs associated with this incident.</p>
                )}
              </div>

              {/* Assigned info */}
              <div className="pt-3 border-t border-slate-800 text-xs text-slate-400 flex items-center justify-between">
                <span>
                  Assigned Analyst: <strong className="text-slate-200">{selectedIncident.assignedTo || 'Unassigned'}</strong>
                </span>
                <span className="text-[11px] font-mono text-slate-500">
                  Updated: {new Date(selectedIncident.updatedAt).toLocaleTimeString()}
                </span>
              </div>
            </div>
          ) : (
            <div className="p-12 text-center text-slate-500 border border-slate-800 rounded-xl">
              Select an incident from the queue to view detailed intelligence and telemetry.
            </div>
          )}
        </div>
      </div>

      <CreateIncidentModal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        onSubmit={handleCreateSubmit}
        isLoading={isSubmitting}
      />
    </div>
  );
}
