import { useState, useEffect, useCallback } from 'react';
import {
  BarChart3,
  Clock,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Shield,
  Activity,
  Users,
  RefreshCw,
  TrendingUp,
} from 'lucide-react';
import type { SOCMetricsResponse } from '@sentinelflow/shared';
import { getSocMetrics } from '../../services/api';
import { useAuth } from '../../context/AuthContext';

export function SocAnalyticsView() {
  const { activeOrganization } = useAuth();
  const [metrics, setMetrics] = useState<SOCMetricsResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchMetrics = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await getSocMetrics();
      setMetrics(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to load SOC analytics');
    } finally {
      setIsLoading(false);
    }
  }, [activeOrganization]);

  useEffect(() => {
    fetchMetrics();
  }, [fetchMetrics]);

  if (isLoading && !metrics) {
    return (
      <div className="p-12 flex flex-col items-center justify-center space-y-3 text-slate-400">
        <div className="w-8 h-8 border-2 border-emerald-500/20 border-t-emerald-400 rounded-full animate-spin" />
        <p className="text-xs font-mono uppercase tracking-wider text-slate-500">
          Calculating SOC Telemetry & MTTR / MTTA Metrics...
        </p>
      </div>
    );
  }

  if (error && !metrics) {
    return (
      <div className="p-6 bg-red-950/20 border border-red-900/40 rounded-xl text-center space-y-3">
        <AlertTriangle className="w-8 h-8 text-rose-400 mx-auto" />
        <p className="text-sm text-rose-300">{error}</p>
        <button
          onClick={fetchMetrics}
          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-semibold rounded-lg text-slate-200 transition"
        >
          Retry
        </button>
      </div>
    );
  }

  const overview = metrics?.overview || {
    totalIncidents: 0,
    openIncidents: 0,
    resolvedIncidents: 0,
    activeAlertsCount: 0,
    criticalIncidentsCount: 0,
    meanTimeToAcknowledgeMinutes: 0,
    meanTimeToResolveMinutes: 0,
  };

  const severity = metrics?.severityDistribution || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const maxSeverityCount = Math.max(severity.CRITICAL, severity.HIGH, severity.MEDIUM, severity.LOW, 1);

  const alertTrends = metrics?.alertTrends || [];
  const maxTrendAlerts = Math.max(...alertTrends.map((t) => t.count), 1);

  return (
    <div className="space-y-6">
      {/* Header bar */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center space-x-2">
            <BarChart3 className="w-5 h-5 text-emerald-400" />
            <span>SOC Operational Performance & Analytics</span>
          </h2>
          <p className="text-xs text-slate-400">
            Real-time incident response times, workload balancing, and telemetry trends for{' '}
            <span className="text-slate-200 font-semibold">{activeOrganization?.organizationName}</span>
          </p>
        </div>

        <button
          onClick={fetchMetrics}
          disabled={isLoading}
          className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 text-xs font-medium rounded-lg flex items-center space-x-1.5 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-emerald-400' : ''}`} />
          <span>Refresh Analytics</span>
        </button>
      </div>

      {/* KPI Performance Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* MTTA */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
              Mean Time to Acknowledge
            </p>
            <div className="flex items-baseline space-x-1.5 mt-1">
              <h3 className="text-2xl font-bold text-white font-mono">
                {overview.meanTimeToAcknowledgeMinutes}
              </h3>
              <span className="text-xs text-slate-400 font-medium">min</span>
            </div>
            <p className="text-[11px] text-emerald-400 mt-1 flex items-center">
              <TrendingUp className="w-3 h-3 mr-1" />
              Target: &lt; 15 min (MTTA)
            </p>
          </div>
          <div className="p-3 bg-amber-500/10 rounded-lg text-amber-400">
            <Clock className="w-5 h-5" />
          </div>
        </div>

        {/* MTTR */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
              Mean Time to Resolve
            </p>
            <div className="flex items-baseline space-x-1.5 mt-1">
              <h3 className="text-2xl font-bold text-white font-mono">
                {overview.meanTimeToResolveMinutes}
              </h3>
              <span className="text-xs text-slate-400 font-medium">min</span>
            </div>
            <p className="text-[11px] text-emerald-400 mt-1 flex items-center">
              <CheckCircle2 className="w-3 h-3 mr-1" />
              Target: &lt; 60 min (MTTR)
            </p>
          </div>
          <div className="p-3 bg-emerald-500/10 rounded-lg text-emerald-400">
            <CheckCircle2 className="w-5 h-5" />
          </div>
        </div>

        {/* Open vs Resolved */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
              Active vs Closed Incidents
            </p>
            <div className="flex items-baseline space-x-2 mt-1">
              <h3 className="text-2xl font-bold text-rose-400 font-mono">{overview.openIncidents}</h3>
              <span className="text-xs text-slate-400">open /</span>
              <span className="text-lg font-bold text-emerald-400 font-mono">{overview.resolvedIncidents}</span>
              <span className="text-xs text-slate-400">closed</span>
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              {overview.totalIncidents} total incidents tracked
            </p>
          </div>
          <div className="p-3 bg-rose-500/10 rounded-lg text-rose-400">
            <Flame className="w-5 h-5" />
          </div>
        </div>

        {/* Ingested Alerts */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
              Security Telemetry Stream
            </p>
            <div className="flex items-baseline space-x-1.5 mt-1">
              <h3 className="text-2xl font-bold text-cyan-400 font-mono">
                {overview.activeAlertsCount}
              </h3>
              <span className="text-xs text-slate-400 font-medium">events</span>
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              SIEM, EDR & CloudTrail sources
            </p>
          </div>
          <div className="p-3 bg-cyan-500/10 rounded-lg text-cyan-400">
            <Activity className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Analytics Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Distribution */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center space-x-2">
              <Shield className="w-4 h-4 text-emerald-400" />
              <span>Incident Severity Breakdown</span>
            </h3>
            <span className="text-xs text-slate-400 font-mono">{overview.totalIncidents} Total</span>
          </div>

          <div className="space-y-3">
            {/* Critical */}
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-red-400 font-medium">CRITICAL</span>
                <span className="font-mono text-slate-300">{severity.CRITICAL}</span>
              </div>
              <div className="w-full bg-slate-800 h-2.5 rounded-full overflow-hidden">
                <div
                  className="bg-red-500 h-full rounded-full transition-all duration-500"
                  style={{ width: `${(severity.CRITICAL / maxSeverityCount) * 100}%` }}
                />
              </div>
            </div>

            {/* High */}
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-orange-400 font-medium">HIGH</span>
                <span className="font-mono text-slate-300">{severity.HIGH}</span>
              </div>
              <div className="w-full bg-slate-800 h-2.5 rounded-full overflow-hidden">
                <div
                  className="bg-orange-500 h-full rounded-full transition-all duration-500"
                  style={{ width: `${(severity.HIGH / maxSeverityCount) * 100}%` }}
                />
              </div>
            </div>

            {/* Medium */}
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-amber-400 font-medium">MEDIUM</span>
                <span className="font-mono text-slate-300">{severity.MEDIUM}</span>
              </div>
              <div className="w-full bg-slate-800 h-2.5 rounded-full overflow-hidden">
                <div
                  className="bg-amber-500 h-full rounded-full transition-all duration-500"
                  style={{ width: `${(severity.MEDIUM / maxSeverityCount) * 100}%` }}
                />
              </div>
            </div>

            {/* Low */}
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-blue-400 font-medium">LOW</span>
                <span className="font-mono text-slate-300">{severity.LOW}</span>
              </div>
              <div className="w-full bg-slate-800 h-2.5 rounded-full overflow-hidden">
                <div
                  className="bg-blue-500 h-full rounded-full transition-all duration-500"
                  style={{ width: `${(severity.LOW / maxSeverityCount) * 100}%` }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* 7-Day Alert Trends */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center space-x-2">
              <TrendingUp className="w-4 h-4 text-cyan-400" />
              <span>7-Day Security Alert Ingestion Volume</span>
            </h3>
            <span className="text-xs text-slate-400">Past 7 Days</span>
          </div>

          <div className="h-44 flex items-end justify-between gap-2 pt-6">
            {alertTrends.map((trend) => {
              const heightPercent = Math.max((trend.count / maxTrendAlerts) * 100, 8);
              const dayLabel = trend.date.slice(5); // MM-DD
              return (
                <div key={trend.date} className="flex-1 flex flex-col items-center gap-1 group">
                  <span className="text-[10px] font-mono text-slate-400 opacity-0 group-hover:opacity-100 transition">
                    {trend.count}
                  </span>
                  <div className="w-full bg-slate-800 rounded-t overflow-hidden flex flex-col justify-end" style={{ height: '110px' }}>
                    <div
                      className="w-full bg-gradient-to-t from-cyan-600 to-emerald-400 rounded-t transition-all duration-500 group-hover:brightness-125"
                      style={{ height: `${heightPercent}%` }}
                    />
                  </div>
                  <span className="text-[10px] font-mono text-slate-500 mt-1">{dayLabel}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Analyst Workload Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-200 flex items-center space-x-2">
            <Users className="w-4 h-4 text-purple-400" />
            <span>SOC Analyst Workload & Incident Distribution</span>
          </h3>
          <span className="text-xs text-slate-400">Assigned Open Incidents</span>
        </div>

        {(!metrics?.analystWorkload || metrics.analystWorkload.length === 0) ? (
          <p className="text-xs text-slate-500 italic py-4 text-center">
            No active incidents currently assigned to analysts in this organization.
          </p>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
            {metrics.analystWorkload.map((analyst) => (
              <div
                key={analyst.analystId}
                className="bg-slate-950/60 border border-slate-800/80 rounded-lg p-3 flex items-center justify-between"
              >
                <div className="flex items-center space-x-3">
                  <div className="w-8 h-8 rounded-full bg-purple-500/20 border border-purple-500/30 flex items-center justify-center text-xs font-bold text-purple-300">
                    {analyst.analystName.slice(0, 2).toUpperCase()}
                  </div>
                  <div>
                    <h4 className="text-xs font-semibold text-white">{analyst.analystName}</h4>
                    <p className="text-[10px] text-slate-500 font-mono">SOC Analyst</p>
                  </div>
                </div>
                <div className="text-right">
                  <span className="text-sm font-bold font-mono text-purple-400">
                    {analyst.assignedCount}
                  </span>
                  <p className="text-[10px] text-slate-500">active</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
