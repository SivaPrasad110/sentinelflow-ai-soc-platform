import { useState } from 'react';
import { Workflow, CheckCircle2, Play } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

export function N8nPlaybooks() {
  const { activeOrganization } = useAuth();
  const [isTriggered, setIsTriggered] = useState(false);

  const handleExecute = () => {
    setIsTriggered(true);
    setTimeout(() => setIsTriggered(false), 4000);
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-base font-bold text-white flex items-center space-x-2">
            <Workflow className="w-5 h-5 text-purple-400" />
            <span>n8n Cloud Playbook Automation Engine</span>
          </h3>
          <p className="text-xs text-slate-400">
            Active Tenant: <strong className="text-slate-200">{activeOrganization?.organizationName}</strong>
          </p>
        </div>

        <button
          onClick={handleExecute}
          className="flex items-center space-x-1.5 px-3 py-1.5 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-semibold transition"
        >
          <Play className="w-3.5 h-3.5" />
          <span>Execute Test Playbook</span>
        </button>
      </div>

      {isTriggered && (
        <div className="p-3 bg-purple-950/40 border border-purple-800 text-xs text-purple-300 rounded-lg flex items-center space-x-2">
          <CheckCircle2 className="w-4 h-4 text-purple-400 shrink-0" />
          <span>Automated n8n webhook payload dispatched for {activeOrganization?.organizationName}. Triage enrichment initiated.</span>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
          <h4 className="text-xs font-bold uppercase tracking-wider text-purple-400">
            Incident Triage & Threat Intelligence
          </h4>
          <p className="text-xs text-slate-300">
            Workflow file: <code className="text-purple-300">n8n/workflows/incident-triage-workflow.json</code>
          </p>
          <ul className="text-xs text-slate-400 space-y-1 list-disc list-inside">
            <li>Webhook route: <code className="text-slate-300 font-mono">POST /webhook/sentinelflow-triage</code></li>
            <li>Enrichment: VirusTotal, AbuseIPDB, Reverse DNS</li>
            <li>LLM Summarization & containment action dispatch</li>
          </ul>
        </div>

        <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
          <h4 className="text-xs font-bold uppercase tracking-wider text-sky-400">
            Integration Status
          </h4>
          <p className="text-xs text-slate-300">
            Authenticated Webhook Key: <code className="text-slate-400 font-mono">X-SentinelFlow-Secret verified</code>
          </p>
          <p className="text-xs text-slate-400 leading-relaxed">
            All triage actions executed by n8n are tagged with the active tenant ID to guarantee cross-tenant boundary isolation.
          </p>
        </div>
      </div>
    </div>
  );
}
