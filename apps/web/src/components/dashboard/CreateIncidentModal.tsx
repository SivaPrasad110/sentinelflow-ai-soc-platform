import React, { useState } from 'react';
import { X, ShieldAlert, AlertTriangle } from 'lucide-react';
import type { AlertSeverity, IncidentStatus, IOCType } from '@sentinelflow/shared';

interface CreateIncidentModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (data: {
    title: string;
    description: string;
    severity: AlertSeverity;
    status: IncidentStatus;
    mitigationSteps: string[];
    iocs: Array<{ type: IOCType; value: string; threatScore?: number }>;
  }) => Promise<void>;
  isLoading: boolean;
}

export function CreateIncidentModal({
  isOpen,
  onClose,
  onSubmit,
  isLoading,
}: CreateIncidentModalProps) {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<AlertSeverity>('MEDIUM');
  const [status, setStatus] = useState<IncidentStatus>('NEW');
  const [iocType, setIocType] = useState<IOCType>('IP');
  const [iocValue, setIocValue] = useState('');
  const [mitigations, setMitigations] = useState('');
  const [formError, setFormError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim() || !description.trim()) {
      setFormError('Title and description are required.');
      return;
    }

    const mitigationSteps = mitigations
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);

    const iocs = iocValue.trim()
      ? [
          {
            type: iocType,
            value: iocValue.trim(),
            threatScore: 80,
          },
        ]
      : [];

    try {
      setFormError(null);
      await onSubmit({
        title: title.trim(),
        description: description.trim(),
        severity,
        status,
        mitigationSteps,
        iocs,
      });
      onClose();
    } catch (err: any) {
      setFormError(err.message || 'Failed to create incident.');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-lg p-6 space-y-5 shadow-2xl relative">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center space-x-2 text-white font-semibold">
            <ShieldAlert className="w-5 h-5 text-emerald-400" />
            <span>Create Security Incident</span>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {formError && (
          <div className="p-3 bg-rose-950/40 border border-rose-800 text-xs text-rose-300 rounded-lg flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{formError}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          <div>
            <label className="block text-slate-400 uppercase font-semibold mb-1">Incident Title</label>
            <input
              type="text"
              required
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g. Cobalt Strike Beaconing Detected"
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500 text-xs"
            />
          </div>

          <div>
            <label className="block text-slate-400 uppercase font-semibold mb-1">Description</label>
            <textarea
              required
              rows={3}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Provide event details, host, user context..."
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500 text-xs"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-slate-400 uppercase font-semibold mb-1">Severity</label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as AlertSeverity)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-emerald-500 text-xs"
              >
                <option value="LOW">LOW</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="HIGH">HIGH</option>
                <option value="CRITICAL">CRITICAL</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-400 uppercase font-semibold mb-1">Initial Status</label>
              <select
                value={status}
                onChange={(e) => setStatus(e.target.value as IncidentStatus)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-emerald-500 text-xs"
              >
                <option value="NEW">NEW</option>
                <option value="TRIAGED">TRIAGED</option>
                <option value="INVESTIGATING">INVESTIGATING</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-2">
            <div className="col-span-1">
              <label className="block text-slate-400 uppercase font-semibold mb-1">IOC Type</label>
              <select
                value={iocType}
                onChange={(e) => setIocType(e.target.value as IOCType)}
                className="w-full px-2 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 text-xs"
              >
                <option value="IP">IP</option>
                <option value="DOMAIN">DOMAIN</option>
                <option value="HASH_SHA256">SHA256</option>
                <option value="URL">URL</option>
              </select>
            </div>
            <div className="col-span-2">
              <label className="block text-slate-400 uppercase font-semibold mb-1">IOC Value (Optional)</label>
              <input
                type="text"
                value={iocValue}
                onChange={(e) => setIocValue(e.target.value)}
                placeholder="e.g. 198.51.100.99"
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-600 text-xs font-mono"
              />
            </div>
          </div>

          <div>
            <label className="block text-slate-400 uppercase font-semibold mb-1">
              Mitigation Actions (1 per line)
            </label>
            <textarea
              rows={2}
              value={mitigations}
              onChange={(e) => setMitigations(e.target.value)}
              placeholder="Isolate endpoint WS-01&#10;Reset user credentials"
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-600 text-xs"
            />
          </div>

          <div className="pt-3 border-t border-slate-800 flex items-center justify-end space-x-2">
            <button
              type="button"
              onClick={onClose}
              disabled={isLoading}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isLoading}
              className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:bg-emerald-800 text-white font-semibold transition flex items-center space-x-1"
            >
              {isLoading ? 'Creating...' : 'Create Incident'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
