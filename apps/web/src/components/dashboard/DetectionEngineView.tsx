import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  Sliders,
  Flame,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Plus,
  Trash2,
  ToggleLeft,
  ToggleRight,
  Layers,
  ArrowUpRight,
  RefreshCw,
} from 'lucide-react';
import type {
  DetectionRule,
  SecurityFinding,
  MitreTechnique,
  DetectionRuleType,
  AlertSeverity,
} from '@sentinelflow/shared';
import {
  getDetectionRules,
  createDetectionRule,
  toggleDetectionRule,
  deleteDetectionRule,
  getFindings,
  promoteFindingToIncident,
  dismissFinding,
  getMitreMatrix,
} from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import { useSocket } from '../../context/SocketContext';

interface DetectionEngineViewProps {
  onIncidentCreated?: (incidentId: string) => void;
}

export function DetectionEngineView({ onIncidentCreated }: DetectionEngineViewProps) {
  const { activeOrganization, activeRole } = useAuth();
  const { socket } = useSocket();

  const [activeSubTab, setActiveSubTab] = useState<'findings' | 'rules' | 'mitre'>('findings');
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [mitreMatrix, setMitreMatrix] = useState<Array<{ id: string; name: string; techniques: MitreTechnique[] }>>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Expanded finding rationale drawer
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [escalatingFindingId, setEscalatingFindingId] = useState<string | null>(null);

  // Selected MITRE technique for modal
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechnique | null>(null);

  // Create rule modal
  const [isAddRuleOpen, setIsAddRuleOpen] = useState(false);
  const [isSubmittingRule, setIsSubmittingRule] = useState(false);
  const [ruleModalError, setRuleModalError] = useState<string | null>(null);
  const [newRule, setNewRule] = useState({
    name: '',
    description: '',
    severity: 'HIGH' as AlertSeverity,
    ruleType: 'PATTERN' as DetectionRuleType,
    field: 'title',
    operator: 'CONTAINS' as 'CONTAINS' | 'EQUALS' | 'STARTS_WITH' | 'REGEX',
    value: '',
    mitreTechniqueId: 'T1059.001',
  });

  const canManage = activeRole === 'ADMIN' || activeRole === 'ANALYST';

  const loadData = useCallback(async () => {
    setIsLoading(true);
    try {
      const [rulesData, findingsData, matrixData] = await Promise.all([
        getDetectionRules().catch(() => []),
        getFindings().catch(() => []),
        getMitreMatrix().catch(() => []),
      ]);

      setRules(rulesData);
      setFindings(findingsData);
      setMitreMatrix(matrixData);
    } finally {
      setIsLoading(false);
    }
  }, [activeOrganization]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Real-time WebSocket updates
  useEffect(() => {
    if (!socket) return;

    const handleFindingCreated = (finding: SecurityFinding) => {
      setFindings((prev) => [finding, ...prev.filter((f) => f.id !== finding.id)]);
    };

    const handleFindingUpdated = (updated: SecurityFinding) => {
      setFindings((prev) => prev.map((f) => (f.id === updated.id ? { ...f, ...updated } : f)));
    };

    socket.on('finding:created', handleFindingCreated);
    socket.on('finding:updated', handleFindingUpdated);

    return () => {
      socket.off('finding:created', handleFindingCreated);
      socket.off('finding:updated', handleFindingUpdated);
    };
  }, [socket]);

  const handleToggleRule = async (ruleId: string, currentEnabled: boolean) => {
    try {
      const updated = await toggleDetectionRule(ruleId, !currentEnabled);
      setRules((prev) => prev.map((r) => (r.id === ruleId ? updated : r)));
    } catch (err: any) {
      alert(`Failed to toggle rule: ${err.message}`);
    }
  };

  const handleDeleteRule = async (ruleId: string) => {
    if (!window.confirm('Delete this detection rule?')) return;
    try {
      await deleteDetectionRule(ruleId);
      setRules((prev) => prev.filter((r) => r.id !== ruleId));
    } catch (err: any) {
      alert(`Failed to delete rule: ${err.message}`);
    }
  };

  const handlePromoteFinding = async (findingId: string) => {
    setEscalatingFindingId(findingId);
    try {
      const incident = await promoteFindingToIncident(findingId);
      setFindings((prev) =>
        prev.map((f) =>
          f.id === findingId ? { ...f, status: 'PROMOTED', incidentId: incident.id } : f,
        ),
      );
      if (onIncidentCreated) {
        onIncidentCreated(incident.id);
      }
    } catch (err: any) {
      alert(`Escalation failed: ${err.message}`);
    } finally {
      setEscalatingFindingId(null);
    }
  };

  const handleDismissFinding = async (findingId: string) => {
    try {
      await dismissFinding(findingId, 'Analyst dismissed');
      setFindings((prev) =>
        prev.map((f) => (f.id === findingId ? { ...f, status: 'DISMISSED' } : f)),
      );
    } catch (err: any) {
      alert(`Failed to dismiss: ${err.message}`);
    }
  };

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmittingRule(true);
    setRuleModalError(null);

    try {
      const payload = {
        name: newRule.name.trim(),
        description: newRule.description.trim(),
        severity: newRule.severity,
        ruleType: newRule.ruleType,
        criteria: [
          {
            field: newRule.field,
            operator: newRule.operator,
            value: newRule.value.trim(),
          },
        ],
        mitreTechniqueId: newRule.mitreTechniqueId.trim() || undefined,
        enabled: true,
      };

      await createDetectionRule(payload);
      setIsAddRuleOpen(false);
      setNewRule({
        name: '',
        description: '',
        severity: 'HIGH',
        ruleType: 'PATTERN',
        field: 'title',
        operator: 'CONTAINS',
        value: '',
        mitreTechniqueId: 'T1059.001',
      });
      await loadData();
    } catch (err: any) {
      setRuleModalError(err.message || 'Failed to create detection rule');
    } finally {
      setIsSubmittingRule(false);
    }
  };

  const getRiskScoreColor = (score: number) => {
    if (score >= 80) return 'text-red-400 bg-red-500/10 border-red-500/30';
    if (score >= 60) return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
    if (score >= 35) return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
    return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'MEDIUM':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
      case 'LOW':
      default:
        return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <Sliders className="w-6 h-6 text-sky-400" />
            <h2 className="text-xl font-bold text-white tracking-wide">Detection Engine & Correlated Findings</h2>
            <span className="px-2 py-0.5 rounded text-xs font-mono font-medium bg-sky-500/20 text-sky-400 border border-sky-500/30">
              MITRE ATT&CK Matrix
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Deterministic pattern detection, MITRE Enterprise mapping, and explainable risk scoring
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={() => loadData()}
            disabled={isLoading}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 hover:bg-slate-700 text-slate-200 text-xs font-medium transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          {canManage && (
            <button
              onClick={() => setIsAddRuleOpen(true)}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold shadow-lg shadow-sky-950 transition"
            >
              <Plus className="w-4 h-4" />
              <span>Create Detection Rule</span>
            </button>
          )}
        </div>
      </div>

      {/* Sub Navigation */}
      <div className="flex items-center space-x-1 border-b border-slate-800">
        <button
          onClick={() => setActiveSubTab('findings')}
          className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-medium border-b-2 transition ${
            activeSubTab === 'findings'
              ? 'border-sky-500 text-sky-400 font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Flame className="w-4 h-4 text-orange-400" />
          <span>Correlated Findings</span>
          <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-slate-800 text-slate-300">
            {findings.filter((f) => f.status === 'NEW').length}
          </span>
        </button>

        <button
          onClick={() => setActiveSubTab('rules')}
          className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-medium border-b-2 transition ${
            activeSubTab === 'rules'
              ? 'border-sky-500 text-sky-400 font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Sliders className="w-4 h-4 text-sky-400" />
          <span>Detection Rules</span>
          <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-slate-800 text-slate-300">
            {rules.length}
          </span>
        </button>

        <button
          onClick={() => setActiveSubTab('mitre')}
          className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-medium border-b-2 transition ${
            activeSubTab === 'mitre'
              ? 'border-sky-500 text-sky-400 font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="w-4 h-4 text-purple-400" />
          <span>MITRE ATT&CK Matrix</span>
        </button>
      </div>

      {/* SUB-TAB 1: CORRELATED FINDINGS */}
      {activeSubTab === 'findings' && (
        <div className="space-y-4">
          {findings.length === 0 ? (
            <div className="p-12 text-center rounded-xl bg-slate-900 border border-slate-800 text-slate-500">
              <ShieldAlert className="w-8 h-8 mx-auto mb-2 text-slate-600" />
              <p className="font-semibold text-slate-400">No correlated security findings yet.</p>
              <p className="text-xs text-slate-500 mt-1">
                Findings are generated automatically when incoming alerts match detection rules or verified threat intel IOCs.
              </p>
            </div>
          ) : (
            findings.map((finding) => {
              const isExpanded = expandedFindingId === finding.id;
              const isEscalating = escalatingFindingId === finding.id;
              const isPromoted = finding.status === 'PROMOTED';
              const isDismissed = finding.status === 'DISMISSED';

              return (
                <div
                  key={finding.id}
                  className={`rounded-xl border transition overflow-hidden ${
                    isPromoted
                      ? 'bg-slate-900/40 border-slate-800/60 opacity-80'
                      : isDismissed
                      ? 'bg-slate-900/30 border-slate-800/40 opacity-50'
                      : 'bg-slate-900 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="p-5 flex flex-col md:flex-row md:items-start justify-between gap-4">
                    <div className="space-y-2 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold border ${getSeverityBadge(finding.severity)}`}>
                          {finding.severity}
                        </span>

                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getRiskScoreColor(finding.riskScore)}`}>
                          RISK {Math.round(finding.riskScore)}/100
                        </span>

                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                          isPromoted ? 'bg-purple-500/10 text-purple-400 border-purple-500/20' :
                          isDismissed ? 'bg-slate-800 text-slate-400 border-slate-700' :
                          'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                        }`}>
                          {finding.status}
                        </span>

                        {finding.mitreTechniqueId && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-500/10 text-purple-300 border border-purple-500/20">
                            {finding.mitreTechniqueId}: {finding.mitreTechnique}
                          </span>
                        )}

                        <span className="text-slate-500 text-xs font-mono">
                          {new Date(finding.createdAt).toLocaleTimeString()}
                        </span>
                      </div>

                      <h4 className="text-base font-bold text-white tracking-wide">{finding.title}</h4>
                      <p className="text-xs text-slate-300 whitespace-pre-line font-sans">{finding.description}</p>
                    </div>

                    {/* Actions & Risk Gauge */}
                    <div className="flex flex-col sm:flex-row md:flex-col items-end gap-3 shrink-0">
                      <div className="flex items-center space-x-2">
                        {!isPromoted && !isDismissed && canManage && (
                          <>
                            <button
                              onClick={() => handlePromoteFinding(finding.id)}
                              disabled={isEscalating}
                              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-lg shadow-emerald-950 transition disabled:opacity-50"
                            >
                              <ArrowUpRight className="w-3.5 h-3.5" />
                              <span>{isEscalating ? 'Escalating...' : 'Escalate to Incident'}</span>
                            </button>

                            <button
                              onClick={() => handleDismissFinding(finding.id)}
                              className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 text-xs transition"
                            >
                              Dismiss
                            </button>
                          </>
                        )}

                        {isPromoted && (
                          <div className="flex items-center space-x-1 text-xs text-purple-400 font-mono">
                            <CheckCircle2 className="w-4 h-4" />
                            <span>Escalated to Incident</span>
                          </div>
                        )}
                      </div>

                      <button
                        onClick={() => setExpandedFindingId(isExpanded ? null : finding.id)}
                        className="flex items-center space-x-1 text-xs text-sky-400 hover:text-sky-300 transition font-mono mt-1"
                      >
                        <span>{isExpanded ? 'Hide Rationale' : 'Inspect Risk Score Breakdown'}</span>
                        {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>

                  {/* Expandable Explainable Risk Breakdown */}
                  {isExpanded && finding.riskBreakdown && (
                    <div className="px-5 py-4 bg-slate-950 border-t border-slate-800 text-xs font-mono space-y-3">
                      <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                        <span className="font-bold text-slate-200">EXPLAINABLE RISK FORMULA ANALYSIS</span>
                        <span className="text-slate-400">Deterministic Mathematical Weighting</span>
                      </div>

                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                        <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                          <span className="text-slate-500 block text-[10px]">BASE SEVERITY</span>
                          <span className="text-slate-200 font-bold text-sm">+{finding.riskBreakdown.baseSeverityScore} pts</span>
                        </div>
                        <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                          <span className="text-slate-500 block text-[10px]">THREAT INTEL / IOC</span>
                          <span className="text-slate-200 font-bold text-sm">+{finding.riskBreakdown.iocConfidenceScore} pts</span>
                        </div>
                        <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                          <span className="text-slate-500 block text-[10px]">MITRE TACTIC IMPACT</span>
                          <span className="text-slate-200 font-bold text-sm">+{finding.riskBreakdown.mitreImpactScore} pts</span>
                        </div>
                        <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                          <span className="text-slate-500 block text-[10px]">EVIDENCE BONUS</span>
                          <span className="text-slate-200 font-bold text-sm">+{finding.riskBreakdown.evidenceBonus} pts</span>
                        </div>
                      </div>

                      {finding.riskBreakdown.rationale && (
                        <div className="space-y-1 mt-2">
                          <span className="text-[11px] font-semibold text-slate-400">Scoring Rationale:</span>
                          <ul className="list-disc list-inside text-slate-300 space-y-0.5 text-[11px]">
                            {finding.riskBreakdown.rationale.map((r, idx) => (
                              <li key={idx}>{r}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      )}

      {/* SUB-TAB 2: DETECTION RULES */}
      {activeSubTab === 'rules' && (
        <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between bg-slate-900/60 font-mono text-xs">
            <span className="text-slate-300 font-semibold">Configured Security Detection Rules</span>
            <span className="text-slate-500">{rules.length} rules active</span>
          </div>

          <div className="divide-y divide-slate-800/60">
            {rules.map((rule) => (
              <div key={rule.id} className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 hover:bg-slate-800/30 transition">
                <div className="space-y-1">
                  <div className="flex items-center space-x-2.5">
                    <span className="font-semibold text-sm text-white">{rule.name}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${getSeverityBadge(rule.severity)}`}>
                      {rule.severity}
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                      {rule.ruleType}
                    </span>
                    {rule.mitreTechniqueId && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-500/10 text-purple-300 border border-purple-500/20">
                        {rule.mitreTechniqueId}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-400">{rule.description}</p>
                </div>

                <div className="flex items-center space-x-4 self-end md:self-auto font-mono text-xs">
                  <div className="text-right">
                    <div className="text-slate-300">{rule.triggerCount} triggers</div>
                    <div className="text-[11px] text-slate-500">
                      {rule.lastTriggeredAt ? new Date(rule.lastTriggeredAt).toLocaleTimeString() : 'Never'}
                    </div>
                  </div>

                  {canManage && (
                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => handleToggleRule(rule.id, rule.enabled)}
                        className={`p-1 rounded text-lg transition ${
                          rule.enabled ? 'text-emerald-400 hover:text-emerald-300' : 'text-slate-600 hover:text-slate-400'
                        }`}
                        title={rule.enabled ? 'Disable rule' : 'Enable rule'}
                      >
                        {rule.enabled ? <ToggleRight className="w-6 h-6" /> : <ToggleLeft className="w-6 h-6" />}
                      </button>

                      {activeRole === 'ADMIN' && (
                        <button
                          onClick={() => handleDeleteRule(rule.id)}
                          className="p-1.5 rounded hover:bg-red-500/10 text-slate-500 hover:text-red-400 transition"
                          title="Delete rule"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUB-TAB 3: MITRE ATT&CK MATRIX NAVIGATOR */}
      {activeSubTab === 'mitre' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between">
            <div>
              <h3 className="font-bold text-sm text-white">Enterprise ATT&CK Tactical Matrix</h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Officially validated MITRE tactics and techniques. Techniques covered by detection rules are highlighted.
              </p>
            </div>
            <div className="flex items-center space-x-3 text-xs font-mono">
              <div className="flex items-center space-x-1.5">
                <div className="w-2.5 h-2.5 rounded-full bg-emerald-400" />
                <span className="text-slate-300">Rule Active</span>
              </div>
              <div className="flex items-center space-x-1.5">
                <div className="w-2.5 h-2.5 rounded-full bg-purple-400" />
                <span className="text-slate-300">Finding Correlated</span>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-3">
            {mitreMatrix.map((tactic) => (
              <div key={tactic.id} className="rounded-xl bg-slate-900 border border-slate-800 flex flex-col overflow-hidden">
                <div className="px-3 py-2 bg-slate-950 border-b border-slate-800">
                  <span className="text-[10px] font-mono text-slate-500 block">{tactic.id}</span>
                  <span className="text-xs font-bold text-slate-200">{tactic.name}</span>
                </div>

                <div className="p-2 space-y-2 flex-1">
                  {tactic.techniques.map((tech) => {
                    const ruleCount = rules.filter((r) => r.mitreTechniqueId === tech.id).length;
                    const findingCount = findings.filter((f) => f.mitreTechniqueId === tech.id).length;

                    return (
                      <div
                        key={tech.id}
                        onClick={() => setSelectedTechnique(tech)}
                        className={`p-2 rounded-lg border cursor-pointer transition text-xs font-mono ${
                          ruleCount > 0
                            ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/20'
                            : findingCount > 0
                            ? 'bg-purple-500/10 border-purple-500/30 text-purple-300 hover:bg-purple-500/20'
                            : 'bg-slate-800/40 border-slate-800 text-slate-400 hover:bg-slate-800 hover:text-slate-200'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-[11px]">{tech.id}</span>
                          {ruleCount > 0 && (
                            <span className="text-[9px] px-1 py-0.2 rounded bg-emerald-500/30 text-emerald-200">
                              {ruleCount} rule
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] font-sans font-medium line-clamp-1 mt-1 text-slate-200">
                          {tech.name}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* MITRE Technique Detail Modal */}
      {selectedTechnique && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <span className="text-xs font-mono text-purple-400">{selectedTechnique.id} ({selectedTechnique.tactic})</span>
                <h3 className="font-bold text-base text-white">{selectedTechnique.name}</h3>
              </div>
              <button onClick={() => setSelectedTechnique(null)} className="text-slate-400 hover:text-white">✕</button>
            </div>

            <div className="space-y-3 text-xs font-sans text-slate-300">
              <div>
                <span className="font-bold text-slate-400 block font-mono text-[11px] mb-1">OFFICIAL MITRE DESCRIPTION</span>
                <p className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-slate-300 leading-relaxed">
                  {selectedTechnique.description}
                </p>
              </div>

              <div>
                <span className="font-bold text-slate-400 block font-mono text-[11px] mb-1">COVERING DETECTION RULES</span>
                {rules.filter((r) => r.mitreTechniqueId === selectedTechnique.id).length === 0 ? (
                  <p className="text-slate-500 italic">No detection rules mapped to this technique yet.</p>
                ) : (
                  <ul className="space-y-1 font-mono">
                    {rules
                      .filter((r) => r.mitreTechniqueId === selectedTechnique.id)
                      .map((r) => (
                        <li key={r.id} className="p-2 rounded bg-slate-800 border border-slate-700 flex items-center justify-between">
                          <span>{r.name}</span>
                          <span className={`px-2 py-0.5 rounded text-[10px] ${getSeverityBadge(r.severity)}`}>{r.severity}</span>
                        </li>
                      ))}
                  </ul>
                )}
              </div>
            </div>

            <div className="flex justify-end pt-3 border-t border-slate-800">
              <button
                onClick={() => setSelectedTechnique(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create Detection Rule Modal */}
      {isAddRuleOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Plus className="w-5 h-5 text-sky-400" />
                <h3 className="font-bold text-base text-white">Create Detection Rule</h3>
              </div>
              <button onClick={() => setIsAddRuleOpen(false)} className="text-slate-400 hover:text-white">✕</button>
            </div>

            {ruleModalError && (
              <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono">
                {ruleModalError}
              </div>
            )}

            <form onSubmit={handleCreateRule} className="space-y-4 text-xs font-sans">
              <div>
                <label className="block text-slate-400 mb-1 font-mono">Rule Name *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Cobalt Strike C2 Named Pipe Detection"
                  value={newRule.name}
                  onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-200"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-mono">Description *</label>
                <input
                  type="text"
                  required
                  placeholder="Detects suspicious named pipes matching known beacon profiles"
                  value={newRule.description}
                  onChange={(e) => setNewRule({ ...newRule, description: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-200"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1 font-mono">Severity</label>
                  <select
                    value={newRule.severity}
                    onChange={(e) => setNewRule({ ...newRule, severity: e.target.value as AlertSeverity })}
                    className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-200"
                  >
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1 font-mono">Rule Type</label>
                  <select
                    value={newRule.ruleType}
                    onChange={(e) => setNewRule({ ...newRule, ruleType: e.target.value as DetectionRuleType })}
                    className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-200"
                  >
                    <option value="PATTERN">Pattern</option>
                    <option value="IOC_MATCH">IOC Match</option>
                    <option value="THRESHOLD">Threshold</option>
                  </select>
                </div>
              </div>

              {/* Criterion builder */}
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                <span className="font-mono text-[11px] text-slate-400 font-semibold block">EVALUATION CRITERION</span>
                <div className="grid grid-cols-3 gap-2">
                  <select
                    value={newRule.field}
                    onChange={(e) => setNewRule({ ...newRule, field: e.target.value })}
                    className="px-2 py-1.5 rounded bg-slate-800 border border-slate-700 text-slate-200 text-xs"
                  >
                    <option value="title">alert.title</option>
                    <option value="description">alert.description</option>
                    <option value="source">alert.source</option>
                    <option value="rawPayload.command">rawPayload.command</option>
                    <option value="rawPayload.ip">rawPayload.ip</option>
                  </select>

                  <select
                    value={newRule.operator}
                    onChange={(e) => setNewRule({ ...newRule, operator: e.target.value as any })}
                    className="px-2 py-1.5 rounded bg-slate-800 border border-slate-700 text-slate-200 text-xs"
                  >
                    <option value="CONTAINS">CONTAINS</option>
                    <option value="EQUALS">EQUALS</option>
                    <option value="STARTS_WITH">STARTS_WITH</option>
                    <option value="REGEX">REGEX</option>
                  </select>

                  <input
                    type="text"
                    required
                    placeholder="Value to match..."
                    value={newRule.value}
                    onChange={(e) => setNewRule({ ...newRule, value: e.target.value })}
                    className="px-2 py-1.5 rounded bg-slate-800 border border-slate-700 text-slate-200 text-xs font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-mono">MITRE ATT&CK Technique</label>
                <select
                  value={newRule.mitreTechniqueId}
                  onChange={(e) => setNewRule({ ...newRule, mitreTechniqueId: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-200 font-mono text-xs"
                >
                  <option value="T1059.001">T1059.001 - PowerShell (Execution)</option>
                  <option value="T1071.001">T1071.001 - Web Protocols (Command and Control)</option>
                  <option value="T1003.001">T1003.001 - LSASS Memory Dumping (Credential Access)</option>
                  <option value="T1486">T1486 - Data Encrypted for Impact (Impact)</option>
                  <option value="T1566">T1566 - Phishing (Initial Access)</option>
                  <option value="T1190">T1190 - Exploit Public-Facing Application (Initial Access)</option>
                  <option value="T1053.005">T1053.005 - Scheduled Task (Persistence)</option>
                  <option value="T1078">T1078 - Valid Accounts (Privilege Escalation)</option>
                  <option value="T1027">T1027 - Obfuscated Files or Information (Defense Evasion)</option>
                </select>
              </div>

              <div className="flex items-center justify-end space-x-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsAddRuleOpen(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmittingRule}
                  className="px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-white font-semibold transition"
                >
                  {isSubmittingRule ? 'Creating...' : 'Create Rule'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
