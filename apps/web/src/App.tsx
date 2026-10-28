import { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  Activity,
  Cpu,
  Workflow,
  Flame,
  AlertTriangle,
  CheckCircle2,
} from 'lucide-react';
import type { Incident, SecurityAlert, SystemHealthResponse } from '@sentinelflow/shared';
import { AuthProvider, useAuth } from './context/AuthContext';
import { secureFetch } from './services/api';
import { LoginPage } from './components/auth/LoginPage';
import { Navbar } from './components/dashboard/Navbar';
import { IncidentsQueue } from './components/dashboard/IncidentsQueue';
import { AlertsStream } from './components/dashboard/AlertsStream';
import { N8nPlaybooks } from './components/dashboard/N8nPlaybooks';

function Dashboard() {
  const { activeOrganization, activeRole } = useAuth();

  const [activeTab, setActiveTab] = useState<'incidents' | 'alerts' | 'n8n'>('incidents');
  const [health, setHealth] = useState<SystemHealthResponse | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);

  const [isLoadingHealth, setIsLoadingHealth] = useState<boolean>(false);
  const [isLoadingIncidents, setIsLoadingIncidents] = useState<boolean>(false);
  const [isLoadingAlerts, setIsLoadingAlerts] = useState<boolean>(false);

  const [incidentsError, setIncidentsError] = useState<string | null>(null);
  const [alertsError, setAlertsError] = useState<string | null>(null);

  const fetchHealth = useCallback(async () => {
    setIsLoadingHealth(true);
    try {
      const res = await secureFetch('/api/v1/health');
      if (res.ok) {
        const data = await res.json();
        setHealth(data);
      }
    } catch {
      // health probe degraded
    } finally {
      setIsLoadingHealth(false);
    }
  }, []);

  const fetchIncidents = useCallback(async () => {
    if (!activeOrganization) return;
    setIsLoadingIncidents(true);
    setIncidentsError(null);

    try {
      const res = await secureFetch('/api/v1/incidents');
      if (!res.ok) {
        if (res.status === 403) {
          throw new Error('Unauthorized: you lack access to incidents in this organization.');
        }
        throw new Error(`Failed to load incidents (HTTP ${res.status}).`);
      }
      const data: Incident[] = await res.json();
      setIncidents(data);
      if (data.length > 0) {
        setSelectedIncident(data[0]);
      } else {
        setSelectedIncident(null);
      }
    } catch (err: any) {
      setIncidentsError(err.message || 'Error fetching incidents from PostgreSQL.');
      setIncidents([]);
      setSelectedIncident(null);
    } finally {
      setIsLoadingIncidents(false);
    }
  }, [activeOrganization]);

  const fetchAlerts = useCallback(async () => {
    if (!activeOrganization) return;
    setIsLoadingAlerts(true);
    setAlertsError(null);

    try {
      const res = await secureFetch('/api/v1/alerts');
      if (!res.ok) {
        throw new Error(`Failed to load alerts (HTTP ${res.status}).`);
      }
      const data: SecurityAlert[] = await res.json();
      setAlerts(data);
    } catch (err: any) {
      setAlertsError(err.message || 'Error fetching alerts from PostgreSQL.');
      setAlerts([]);
    } finally {
      setIsLoadingAlerts(false);
    }
  }, [activeOrganization]);

  // Whenever the active organization changes, clear cached data and fetch fresh scoped data
  useEffect(() => {
    setIncidents([]);
    setAlerts([]);
    setSelectedIncident(null);
    fetchHealth();
    fetchIncidents();
    fetchAlerts();
  }, [activeOrganization, fetchHealth, fetchIncidents, fetchAlerts]);

  const handleRefreshAll = () => {
    fetchHealth();
    fetchIncidents();
    fetchAlerts();
  };

  const handleCreateIncident = async (payload: any) => {
    const res = await secureFetch('/api/v1/incidents', {
      method: 'POST',
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.message || 'Failed to create incident in database.');
    }

    await fetchIncidents();
  };

  const handleDeleteIncident = async (id: string) => {
    if (!window.confirm(`Are you sure you want to delete incident ${id}?`)) return;

    const res = await secureFetch(`/api/v1/incidents/${id}`, {
      method: 'DELETE',
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      alert(err.message || 'Failed to delete incident.');
      return;
    }

    await fetchIncidents();
  };

  const handleIngestAlert = async (payload: any) => {
    const res = await secureFetch('/api/v1/alerts', {
      method: 'POST',
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.message || 'Failed to ingest alert in database.');
    }

    await fetchAlerts();
  };

  const criticalCount = incidents.filter((i) => i.severity === 'CRITICAL').length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-emerald-500/30">
      <Navbar
        health={health}
        onRefresh={handleRefreshAll}
        isLoading={isLoadingIncidents || isLoadingAlerts || isLoadingHealth}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6">
        {/* KPI Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
            <div>
              <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Scoped Incidents</p>
              <h3 className="text-2xl font-bold text-white mt-1">{incidents.length}</h3>
              <p className={`text-xs mt-1 flex items-center ${criticalCount > 0 ? 'text-rose-400' : 'text-slate-400'}`}>
                {criticalCount > 0 ? (
                  <>
                    <AlertTriangle className="w-3 h-3 mr-1" />
                    {criticalCount} Critical Action Required
                  </>
                ) : (
                  <span>0 Critical Incidents</span>
                )}
              </p>
            </div>
            <div className="p-3 bg-rose-500/10 rounded-lg text-rose-400">
              <Flame className="w-5 h-5" />
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
            <div>
              <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Active Alerts</p>
              <h3 className="text-2xl font-bold text-white mt-1">{alerts.length}</h3>
              <p className="text-xs text-emerald-400 mt-1 flex items-center">
                <CheckCircle2 className="w-3 h-3 mr-1" />
                Stream Filtered to Org
              </p>
            </div>
            <div className="p-3 bg-amber-500/10 rounded-lg text-amber-400">
              <Activity className="w-5 h-5" />
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
            <div>
              <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Active Role</p>
              <h3 className="text-2xl font-bold text-emerald-400 mt-1 uppercase">{activeRole || 'VIEWER'}</h3>
              <p className="text-xs text-slate-400 mt-1">
                {activeRole === 'ADMIN'
                  ? 'Full Operations & Delete'
                  : activeRole === 'ANALYST'
                  ? 'Triage & Ingestion Access'
                  : 'Read-Only Audit Mode'}
              </p>
            </div>
            <div className="p-3 bg-emerald-500/10 rounded-lg text-emerald-400">
              <Cpu className="w-5 h-5" />
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
            <div>
              <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Active Boundary</p>
              <h3 className="text-sm font-bold text-purple-400 mt-1 truncate max-w-[150px]">
                {activeOrganization?.organizationName}
              </h3>
              <p className="text-[11px] text-slate-500 font-mono mt-1 truncate max-w-[150px]">
                {activeOrganization?.organizationId}
              </p>
            </div>
            <div className="p-3 bg-purple-500/10 rounded-lg text-purple-400">
              <Workflow className="w-5 h-5" />
            </div>
          </div>
        </div>

        {/* Tab Selection */}
        <div className="flex border-b border-slate-800 space-x-6">
          <button
            onClick={() => setActiveTab('incidents')}
            className={`pb-3 text-sm font-semibold flex items-center space-x-2 transition border-b-2 ${
              activeTab === 'incidents'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldAlert className="w-4 h-4" />
            <span>Incidents Queue</span>
            <span className="ml-1 px-1.5 py-0.2 bg-slate-800 rounded-full text-xs text-slate-300">
              {incidents.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('alerts')}
            className={`pb-3 text-sm font-semibold flex items-center space-x-2 transition border-b-2 ${
              activeTab === 'alerts'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Activity className="w-4 h-4" />
            <span>Raw Alerts Stream</span>
            <span className="ml-1 px-1.5 py-0.2 bg-slate-800 rounded-full text-xs text-slate-300">
              {alerts.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('n8n')}
            className={`pb-3 text-sm font-semibold flex items-center space-x-2 transition border-b-2 ${
              activeTab === 'n8n'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Workflow className="w-4 h-4" />
            <span>n8n Playbook Automation</span>
          </button>
        </div>

        {/* Tab Views */}
        {activeTab === 'incidents' && (
          <IncidentsQueue
            incidents={incidents}
            isLoading={isLoadingIncidents}
            error={incidentsError}
            onRefresh={fetchIncidents}
            onCreateIncident={handleCreateIncident}
            onDeleteIncident={handleDeleteIncident}
            selectedIncident={selectedIncident}
            onSelectIncident={setSelectedIncident}
          />
        )}

        {activeTab === 'alerts' && (
          <AlertsStream
            alerts={alerts}
            isLoading={isLoadingAlerts}
            error={alertsError}
            onRefresh={fetchAlerts}
            onIngestAlert={handleIngestAlert}
          />
        )}

        {activeTab === 'n8n' && <N8nPlaybooks />}
      </main>
    </div>
  );
}

function AppContent() {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center space-y-4 text-slate-400">
        <div className="w-10 h-10 border-2 border-emerald-500/20 border-t-emerald-400 rounded-full animate-spin" />
        <p className="text-xs font-mono tracking-wider uppercase text-slate-500">
          Initializing Secure SentinelFlow Session...
        </p>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <LoginPage />;
  }

  return <Dashboard />;
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}
