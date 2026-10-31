import { useState, useEffect, useCallback } from 'react';
import {
  ShieldCheck,
  RefreshCw,
  AlertTriangle,
  User,
  Clock,
  Filter,
} from 'lucide-react';
import type { AuditLogRecord } from '@sentinelflow/shared';
import { getAuditLogs } from '../../services/api';
import { useAuth } from '../../context/AuthContext';

export function AuditLogsView() {
  const { activeOrganization } = useAuth();
  const [logs, setLogs] = useState<AuditLogRecord[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedAction, setSelectedAction] = useState<string>('ALL');

  const fetchLogs = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await getAuditLogs(
        50,
        selectedAction === 'ALL' ? undefined : selectedAction,
      );
      setLogs(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to load security audit trail');
    } finally {
      setIsLoading(false);
    }
  }, [selectedAction, activeOrganization]);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  const getActionBadge = (action: string) => {
    if (action.includes('DELETE')) {
      return 'bg-red-500/10 text-red-400 border border-red-500/20';
    }
    if (action.includes('CREATE') || action.includes('REGISTER')) {
      return 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20';
    }
    if (action.includes('ASSIGN') || action.includes('UPDATE')) {
      return 'bg-amber-500/10 text-amber-400 border border-amber-500/20';
    }
    if (action.includes('AUTH')) {
      return 'bg-purple-500/10 text-purple-400 border border-purple-500/20';
    }
    return 'bg-slate-800 text-slate-300 border border-slate-700';
  };

  return (
    <div className="space-y-6">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center space-x-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            <span>Immutable Security Audit Log</span>
          </h2>
          <p className="text-xs text-slate-400">
            Append-only audit trail recording authentication, status changes, assignments, and analyst actions
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-1.5 bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-slate-300">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={selectedAction}
              onChange={(e) => setSelectedAction(e.target.value)}
              className="bg-transparent border-none text-slate-200 text-xs focus:outline-none"
            >
              <option value="ALL">All Actions</option>
              <option value="AUTH_LOGIN">AUTH_LOGIN</option>
              <option value="AUTH_LOGOUT">AUTH_LOGOUT</option>
              <option value="INCIDENT_CREATE">INCIDENT_CREATE</option>
              <option value="INCIDENT_UPDATE">INCIDENT_UPDATE</option>
              <option value="INCIDENT_ASSIGN">INCIDENT_ASSIGN</option>
              <option value="INCIDENT_DELETE">INCIDENT_DELETE</option>
              <option value="COMMENT_CREATE">COMMENT_CREATE</option>
              <option value="ALERT_CREATE">ALERT_CREATE</option>
              <option value="TRIAGE_COMPLETED">TRIAGE_COMPLETED</option>
            </select>
          </div>

          <button
            onClick={fetchLogs}
            disabled={isLoading}
            className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 text-xs font-medium rounded-lg flex items-center space-x-1.5 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-emerald-400' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-red-950/20 border border-red-900/40 rounded-xl flex items-center space-x-3 text-rose-300 text-xs">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Audit Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 uppercase font-mono text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Actor</th>
                <th className="py-3 px-4">Entity</th>
                <th className="py-3 px-4">Details / Metadata</th>
                <th className="py-3 px-4">Source IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {logs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500 italic">
                    {isLoading ? 'Loading security audit logs...' : 'No audit records found matching this filter.'}
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-800/30 transition">
                    <td className="py-3 px-4 text-slate-400 font-mono whitespace-nowrap">
                      <div className="flex items-center space-x-1.5">
                        <Clock className="w-3 h-3 text-slate-500" />
                        <span>{new Date(log.createdAt).toLocaleString()}</span>
                      </div>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-mono font-semibold ${getActionBadge(log.action)}`}>
                        {log.action}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-300 whitespace-nowrap">
                      <div className="flex items-center space-x-1.5">
                        <User className="w-3 h-3 text-slate-500" />
                        <span>{log.userEmail || 'System / Unauth'}</span>
                      </div>
                    </td>
                    <td className="py-3 px-4 text-slate-400 font-mono text-[11px] whitespace-nowrap">
                      <span className="text-slate-300">{log.entityType}</span>
                      {log.entityId && (
                        <span className="text-slate-500 ml-1 text-[10px]">
                          ({log.entityId.slice(0, 8)}...)
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-slate-400 max-w-md truncate">
                      {log.details ? (
                        <code className="text-[11px] font-mono text-slate-400 bg-slate-950 px-1.5 py-0.5 rounded">
                          {JSON.stringify(log.details)}
                        </code>
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-slate-400 font-mono text-[11px] whitespace-nowrap">
                      {log.ipAddress || '127.0.0.1'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
