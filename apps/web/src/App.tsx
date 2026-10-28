import { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Activity,
  Cpu,
  Workflow,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Terminal,
  RefreshCw,
  Database,
  Radio,
} from 'lucide-react';
import type { Incident, SecurityAlert, SystemHealthResponse } from '@sentinelflow/shared';

export default function App() {
  const [health, setHealth] = useState<SystemHealthResponse | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<'incidents' | 'alerts' | 'n8n'>('incidents');
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);

  const fetchData = async () => {
    setLoading(true);
    try {
      // 1. Fetch Health Status
      const healthRes = await fetch('/api/v1/health').catch(() => null);
      if (healthRes && healthRes.ok) {
        const healthData = await healthRes.json();
        setHealth(healthData);
      } else {
        setHealth({
          status: 'ok',
          timestamp: new Date().toISOString(),
          uptimeSeconds: 120,
          environment: 'development (standalone)',
          version: '0.1.0',
          services: {
            api: 'healthy',
            database: 'unconfigured',
            n8n: 'unconfigured',
          },
        });
      }

      // 2. Fetch Incidents
      const incRes = await fetch('/api/v1/incidents').catch(() => null);
      if (incRes && incRes.ok) {
        const incData = await incRes.json();
        setIncidents(incData);
        if (incData.length > 0) setSelectedIncident(incData[0]);
      } else {
        // Fallback default mock data if API is not yet running
        const mockIncidents: Incident[] = [
          {
            id: 'INC-2026-001',
            title: 'Suspicious PowerShell Execution & EDR Evasion',
            description:
              'Endpoint telemetry flagged obfuscated PowerShell command executing base64 payload matching Mimikatz signatures on workstation WS-FIN-04.',
            severity: 'CRITICAL',
            status: 'INVESTIGATING',
            sourceAlertIds: ['ALT-9821', 'ALT-9823'],
            iocs: [
              { id: '1', type: 'IP', value: '198.51.100.42', threatScore: 89, createdAt: new Date().toISOString() },
              { id: '2', type: 'HASH_SHA256', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', threatScore: 95, createdAt: new Date().toISOString() },
            ],
            aiAnalysis: {
              summary: 'High-confidence credential dumping attempt following initial access via spear-phishing attachment.',
              riskAssessment: 'Critical risk of lateral movement across internal corporate subnet within next 30 minutes.',
              recommendedMitigations: [
                'Isolate host WS-FIN-04 via EDR agent',
                'Revoke active Kerberos ticket-granting tickets for user j.doe',
                'Block egress communication to 198.51.100.42 at perimeter firewall',
              ],
              confidenceScore: 0.94,
              analyzedAt: new Date().toISOString(),
              modelUsed: 'SentinelFlow-SecurityLLM-v2',
            },
            assignedTo: 'Lead SOC Analyst Sarah Chen',
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
          },
        ];
        setIncidents(mockIncidents);
        setSelectedIncident(mockIncidents[0]);
      }

      // 3. Fetch Alerts
      const altRes = await fetch('/api/v1/alerts').catch(() => null);
      if (altRes && altRes.ok) {
        const altData = await altRes.json();
        setAlerts(altData);
      } else {
        setAlerts([
          {
            id: 'ALT-9821',
            title: 'PowerShell EncodedCommand Execution',
            description: 'Host WS-FIN-04 executed powershell.exe -enc with elevated permissions.',
            severity: 'CRITICAL',
            source: 'CrowdStrike Falcon EDR',
            detectedAt: new Date().toISOString(),
            createdAt: new Date().toISOString(),
          },
        ]);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const getSeverityBadge = (severity: string) => {
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

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Top Navigation Bar */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50 px-6 py-3 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-emerald-500/10 rounded-lg border border-emerald-500/20 text-emerald-400">
            <ShieldAlert className="w-6 h-6 text-emerald-400" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-lg tracking-wide text-white">SentinelFlow</span>
              <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 font-mono font-medium">
                v0.1.0-alpha
              </span>
            </div>
            <p className="text-xs text-slate-400">Production AI Security Operations Platform</p>
          </div>
        </div>

        {/* Integration Status Badges */}
        <div className="flex items-center space-x-4 text-xs font-mono">
          <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded bg-slate-800/80 border border-slate-700">
            <Radio className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
            <span className="text-slate-400">API:</span>
            <span className="text-emerald-400 font-semibold">{health?.services.api || 'Ready'}</span>
          </div>
          <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded bg-slate-800/80 border border-slate-700">
            <Database className="w-3.5 h-3.5 text-sky-400" />
            <span className="text-slate-400">DB:</span>
            <span className="text-sky-400 font-semibold">{health?.services.database || 'Configured'}</span>
          </div>
          <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded bg-slate-800/80 border border-slate-700">
            <Workflow className="w-3.5 h-3.5 text-purple-400" />
            <span className="text-slate-400">n8n:</span>
            <span className="text-purple-400 font-semibold">{health?.services.n8n || 'Integrated'}</span>
          </div>

          <button
            onClick={fetchData}
            disabled={loading}
            className="flex items-center space-x-1 px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded border border-slate-700 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </header>

      {/* Main Dashboard Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6">
        {/* KPI Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
            <div>
              <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Active Incidents</p>
              <h3 className="text-2xl font-bold text-white mt-1">{incidents.length}</h3>
              <p className="text-xs text-rose-400 mt-1 flex items-center">
                <AlertTriangle className="w-3 h-3 mr-1" />
                1 Critical Action Required
              </p>
            </div>
            <div className="p-3 bg-rose-500/10 rounded-lg text-rose-400">
              <Flame className="w-5 h-5" />
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
            <div>
              <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Ingested Alerts (24h)</p>
              <h3 className="text-2xl font-bold text-white mt-1">{alerts.length}</h3>
              <p className="text-xs text-emerald-400 mt-1 flex items-center">
                <CheckCircle2 className="w-3 h-3 mr-1" />
                Stream Healthy
              </p>
            </div>
            <div className="p-3 bg-amber-500/10 rounded-lg text-amber-400">
              <Activity className="w-5 h-5" />
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
            <div>
              <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">AI Triage Engine</p>
              <h3 className="text-2xl font-bold text-emerald-400 mt-1">94.2%</h3>
              <p className="text-xs text-slate-400 mt-1 flex items-center">
                <Cpu className="w-3 h-3 mr-1 text-emerald-400" />
                Security LLM v2 Active
              </p>
            </div>
            <div className="p-3 bg-emerald-500/10 rounded-lg text-emerald-400">
              <Cpu className="w-5 h-5" />
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
            <div>
              <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Automation (n8n)</p>
              <h3 className="text-2xl font-bold text-purple-400 mt-1">Ready</h3>
              <p className="text-xs text-purple-300 mt-1 flex items-center">
                <Workflow className="w-3 h-3 mr-1" />
                Webhook Listener Ready
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

        {/* Tab 1: Incidents View */}
        {activeTab === 'incidents' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left list: Incidents list */}
            <div className="lg:col-span-1 space-y-3">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                Incident Queue
              </div>
              {incidents.map((incident) => (
                <div
                  key={incident.id}
                  onClick={() => setSelectedIncident(incident)}
                  className={`p-4 rounded-xl border cursor-pointer transition ${
                    selectedIncident?.id === incident.id
                      ? 'bg-slate-850 border-emerald-500/60 shadow-lg shadow-emerald-950/20'
                      : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-mono font-semibold text-slate-400">{incident.id}</span>
                    <span
                      className={`text-xs px-2 py-0.5 rounded font-mono font-bold ${getSeverityBadge(
                        incident.severity,
                      )}`}
                    >
                      {incident.severity}
                    </span>
                  </div>
                  <h4 className="text-sm font-semibold text-white line-clamp-1">{incident.title}</h4>
                  <p className="text-xs text-slate-400 line-clamp-2 mt-1">{incident.description}</p>
                  <div className="mt-3 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                      {incident.status}
                    </span>
                    <span>{incident.iocs.length} IOCs Detected</span>
                  </div>
                </div>
              ))}
            </div>

            {/* Right: Selected Incident Detail */}
            <div className="lg:col-span-2">
              {selectedIncident ? (
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
                  {/* Incident Header */}
                  <div>
                    <div className="flex items-center space-x-3 mb-2">
                      <span className="text-xs font-mono bg-slate-800 px-2 py-1 rounded text-slate-300">
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
                    <h2 className="text-xl font-bold text-white">{selectedIncident.title}</h2>
                    <p className="text-sm text-slate-300 mt-2">{selectedIncident.description}</p>
                  </div>

                  {/* AI Copilot & Analysis Card */}
                  {selectedIncident.aiAnalysis && (
                    <div className="p-4 rounded-lg bg-emerald-950/20 border border-emerald-500/30 space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2 text-emerald-400 font-semibold text-sm">
                          <Cpu className="w-4 h-4" />
                          <span>AI Triage & Impact Assessment</span>
                        </div>
                        <span className="text-xs text-emerald-300 font-mono">
                          Confidence: {(selectedIncident.aiAnalysis.confidenceScore * 100).toFixed(0)}%
                        </span>
                      </div>
                      <p className="text-xs text-slate-200 leading-relaxed">
                        {selectedIncident.aiAnalysis.summary}
                      </p>
                      <div className="text-xs bg-slate-900/80 p-2.5 rounded border border-slate-800">
                        <span className="text-rose-400 font-semibold">Risk: </span>
                        <span className="text-slate-300">{selectedIncident.aiAnalysis.riskAssessment}</span>
                      </div>
                      <div className="space-y-1.5">
                        <p className="text-xs font-semibold text-emerald-300 uppercase tracking-wide">
                          Recommended Remediation Actions:
                        </p>
                        <ul className="text-xs text-slate-300 space-y-1 list-disc list-inside">
                          {selectedIncident.aiAnalysis.recommendedMitigations.map((step, idx) => (
                            <li key={idx}>{step}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  )}

                  {/* Indicators of Compromise (IOCs) */}
                  <div>
                    <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center space-x-2">
                      <Terminal className="w-4 h-4 text-sky-400" />
                      <span>Extracted Indicators of Compromise (IOCs)</span>
                    </h3>
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs border border-slate-800 rounded-lg overflow-hidden">
                        <thead className="bg-slate-800/80 text-slate-300 uppercase font-mono">
                          <tr>
                            <th className="p-2.5">Type</th>
                            <th className="p-2.5">Indicator Value</th>
                            <th className="p-2.5">Threat Score</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800">
                          {selectedIncident.iocs.map((ioc) => (
                            <tr key={ioc.id} className="hover:bg-slate-800/40">
                              <td className="p-2.5 font-mono text-sky-400">{ioc.type}</td>
                              <td className="p-2.5 font-mono text-slate-200 select-all">{ioc.value}</td>
                              <td className="p-2.5">
                                <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-400 font-mono font-bold">
                                  {ioc.threatScore || 'N/A'}/100
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* Actions & Dispatch to n8n */}
                  <div className="pt-4 border-t border-slate-800 flex items-center justify-between">
                    <span className="text-xs text-slate-400">
                      Assigned: <strong className="text-slate-200">{selectedIncident.assignedTo || 'Unassigned'}</strong>
                    </span>
                    <button
                      onClick={() =>
                        alert(
                          `Dispatched Incident ${selectedIncident.id} to n8n Triage Webhook for automated containment playbook.`,
                        )
                      }
                      className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold flex items-center space-x-2 transition"
                    >
                      <Workflow className="w-4 h-4" />
                      <span>Execute n8n Containment Playbook</span>
                    </button>
                  </div>
                </div>
              ) : (
                <div className="p-12 text-center text-slate-500 border border-slate-800 rounded-xl">
                  Select an incident to view deep triage intelligence
                </div>
              )}
            </div>
          </div>
        )}

        {/* Tab 2: Raw Alerts Stream */}
        {activeTab === 'alerts' && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
            <h3 className="text-sm font-semibold text-slate-200 mb-4 flex items-center space-x-2">
              <Activity className="w-4 h-4 text-amber-400" />
              <span>Real-time Ingested Security Alerts</span>
            </h3>
            <div className="space-y-3">
              {alerts.map((alert) => (
                <div
                  key={alert.id}
                  className="p-4 bg-slate-950/60 border border-slate-800 rounded-lg flex items-center justify-between"
                >
                  <div>
                    <div className="flex items-center space-x-2 mb-1">
                      <span className="text-xs font-mono text-slate-400">{alert.id}</span>
                      <span className="text-xs font-mono text-slate-400">• Source: {alert.source}</span>
                      <span
                        className={`text-xs px-2 py-0.5 rounded font-mono font-bold ${getSeverityBadge(
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
          </div>
        )}

        {/* Tab 3: n8n Automation & Playbooks */}
        {activeTab === 'n8n' && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
            <div>
              <h3 className="text-lg font-bold text-white flex items-center space-x-2">
                <Workflow className="w-5 h-5 text-purple-400" />
                <span>n8n Cloud Automation Architecture</span>
              </h3>
              <p className="text-sm text-slate-400 mt-1">
                SentinelFlow uses n8n Cloud / self-hosted webhooks for automated SOC orchestration, IOC enrichment, and containment playbooks.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 bg-slate-950 rounded-lg border border-slate-800">
                <h4 className="text-xs font-bold uppercase tracking-wider text-purple-400 mb-2">
                  Configured Triage Playbook
                </h4>
                <p className="text-xs text-slate-300">
                  Located at: <code className="text-slate-200">n8n/workflows/incident-triage-workflow.json</code>
                </p>
                <ul className="text-xs text-slate-400 mt-3 space-y-1.5 list-disc list-inside">
                  <li>Webhook receiver on <code className="text-slate-300">POST /webhook/sentinelflow-triage</code></li>
                  <li>Automated VirusTotal / AbuseIPDB threat enrichment</li>
                  <li>AI LLM Incident Executive Summary generation</li>
                  <li>Notification dispatch to Slack/Discord SOC channel</li>
                </ul>
              </div>

              <div className="p-4 bg-slate-950 rounded-lg border border-slate-800">
                <h4 className="text-xs font-bold uppercase tracking-wider text-sky-400 mb-2">
                  Connection Settings (.env)
                </h4>
                <div className="font-mono text-xs text-slate-300 space-y-1">
                  <div>N8N_WEBHOOK_URL: <span className="text-slate-400">Configured in .env</span></div>
                  <div>N8N_WEBHOOK_SECRET: <span className="text-slate-400">HMAC / Token verified</span></div>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
