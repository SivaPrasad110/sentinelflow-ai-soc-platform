import React, { useState, useEffect, useCallback } from 'react';
import {
  Globe,
  Database,
  RefreshCw,
  Search,
  Plus,
  Trash2,
  AlertTriangle,
  Filter,
  Tag,
  Copy,
  Check,
  Zap,
} from 'lucide-react';
import type {
  IndicatorOfCompromise,
  ThreatFeed,
  ThreatIntelStatsResponse,
  IOCType,
  AlertSeverity,
} from '@sentinelflow/shared';
import {
  getIocs,
  createIoc,
  deleteIoc,
  getThreatFeeds,
  syncThreatFeed,
  getThreatIntelStats,
} from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import { useSocket } from '../../context/SocketContext';

export function ThreatIntelView() {
  const { activeOrganization, activeRole } = useAuth();
  const { socket } = useSocket();

  const [stats, setStats] = useState<ThreatIntelStatsResponse | null>(null);
  const [feeds, setFeeds] = useState<ThreatFeed[]>([]);
  const [iocs, setIocs] = useState<IndicatorOfCompromise[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isSyncingFeedId, setIsSyncingFeedId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');

  // Modal
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [modalError, setModalError] = useState<string | null>(null);
  const [newIoc, setNewIoc] = useState({
    type: 'IP' as IOCType,
    value: '',
    severity: 'HIGH' as AlertSeverity,
    confidence: 0.85,
    threatScore: 80,
    description: '',
    tags: '',
    mitreTactics: 'Command and Control',
    mitreTechniques: 'T1071.001',
  });

  const canManage = activeRole === 'ADMIN' || activeRole === 'ANALYST';

  const loadData = useCallback(async () => {
    setIsLoading(true);
    try {
      const [statsData, feedsData, iocsData] = await Promise.all([
        getThreatIntelStats().catch(() => null),
        getThreatFeeds().catch(() => []),
        getIocs({
          query: searchQuery || undefined,
          type: selectedType === 'ALL' ? undefined : selectedType,
          severity: selectedSeverity === 'ALL' ? undefined : selectedSeverity,
        }).catch(() => []),
      ]);

      setStats(statsData);
      setFeeds(feedsData);
      setIocs(iocsData);
    } finally {
      setIsLoading(false);
    }
  }, [searchQuery, selectedType, selectedSeverity, activeOrganization]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // WebSocket real-time updates
  useEffect(() => {
    if (!socket) return;

    const handleIocCreated = (ioc: IndicatorOfCompromise) => {
      setIocs((prev) => [ioc, ...prev.filter((i) => i.id !== ioc.id)]);
      getThreatIntelStats().then(setStats).catch(() => {});
    };

    const handleFeedSynced = (result: any) => {
      setFeeds((prev) =>
        prev.map((f) =>
          f.id === result.feedId
            ? { ...f, status: 'COMPLETED', itemCount: (f.itemCount || 0) + (result.indicatorsImported || 0), lastFetchedAt: new Date().toISOString() }
            : f,
        ),
      );
      getThreatIntelStats().then(setStats).catch(() => {});
    };

    socket.on('ioc:created', handleIocCreated);
    socket.on('feed:synced', handleFeedSynced);

    return () => {
      socket.off('ioc:created', handleIocCreated);
      socket.off('feed:synced', handleFeedSynced);
    };
  }, [socket]);

  const handleSyncFeed = async (feedId: string) => {
    setIsSyncingFeedId(feedId);
    try {
      await syncThreatFeed(feedId);
      await loadData();
    } catch (err: any) {
      alert(`Feed sync failed: ${err.message}`);
    } finally {
      setIsSyncingFeedId(null);
    }
  };

  const handleDeleteIoc = async (id: string) => {
    if (!window.confirm('Are you sure you want to delete this indicator?')) return;
    try {
      await deleteIoc(id);
      setIocs((prev) => prev.filter((i) => i.id !== id));
      getThreatIntelStats().then(setStats).catch(() => {});
    } catch (err: any) {
      alert(`Failed to delete IOC: ${err.message}`);
    }
  };

  const handleCreateIoc = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setModalError(null);

    try {
      const payload = {
        type: newIoc.type,
        value: newIoc.value.trim(),
        severity: newIoc.severity,
        confidence: Number(newIoc.confidence),
        threatScore: Number(newIoc.threatScore),
        description: newIoc.description.trim() || undefined,
        tags: newIoc.tags ? newIoc.tags.split(',').map((t) => t.trim()).filter(Boolean) : [],
        mitreTactics: newIoc.mitreTactics ? [newIoc.mitreTactics.trim()] : [],
        mitreTechniques: newIoc.mitreTechniques ? [newIoc.mitreTechniques.trim()] : [],
      };

      await createIoc(payload);
      setIsAddModalOpen(false);
      setNewIoc({
        type: 'IP',
        value: '',
        severity: 'HIGH',
        confidence: 0.85,
        threatScore: 80,
        description: '',
        tags: '',
        mitreTactics: 'Command and Control',
        mitreTechniques: 'T1071.001',
      });
      await loadData();
    } catch (err: any) {
      setModalError(err.message || 'Failed to create IOC');
    } finally {
      setIsSubmitting(false);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
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

  const getTypeBadge = (type: string) => {
    switch (type) {
      case 'IP':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
      case 'DOMAIN':
        return 'bg-purple-500/10 text-purple-400 border-purple-500/20';
      case 'URL':
        return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20';
      case 'HASH_SHA256':
      case 'HASH_MD5':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
      case 'EMAIL':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/20';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <Globe className="w-6 h-6 text-emerald-400" />
            <h2 className="text-xl font-bold text-white tracking-wide">Threat Intelligence Engine</h2>
            <span className="px-2 py-0.5 rounded text-xs font-mono font-medium bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
              Phase 6 Active
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Automated defensive threat feeds, indicator correlation, and MITRE ATT&CK mapping
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
              onClick={() => setIsAddModalOpen(true)}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-lg shadow-emerald-950 transition"
            >
              <Plus className="w-4 h-4" />
              <span>Add Indicator</span>
            </button>
          )}
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 font-mono">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>TOTAL INDICATORS</span>
            <Database className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-white">{stats?.totalIocs || iocs.length}</div>
          <div className="text-[11px] text-emerald-400 mt-1 flex items-center space-x-1">
            <Zap className="w-3 h-3" />
            <span>{stats?.activeIocs || iocs.length} active indicators</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>DEFENSIVE FEEDS</span>
            <Globe className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-2xl font-bold text-white">{feeds.length}</div>
          <div className="text-[11px] text-slate-400 mt-1">Abuse.ch, ThreatFox, Blocklists</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>HIGH/CRITICAL IOCs</span>
            <AlertTriangle className="w-4 h-4 text-orange-400" />
          </div>
          <div className="text-2xl font-bold text-orange-400">
            {(stats?.iocsBySeverity?.CRITICAL || 0) + (stats?.iocsBySeverity?.HIGH || 0)}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">Verified malicious signatures</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>MITRE TECHNIQUES</span>
            <Tag className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-purple-400">{stats?.mitreCoverageCount || 6}</div>
          <div className="text-[11px] text-slate-400 mt-1">Enterprise ATT&CK covered</div>
        </div>
      </div>

      {/* Defensive Feeds Monitor */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center space-x-2">
            <Globe className="w-4 h-4 text-sky-400" />
            <h3 className="font-semibold text-sm text-white">Ingested Defensive Threat Feeds</h3>
          </div>
          <span className="text-xs text-slate-400 font-mono">Auto-normalized with fallback baseline</span>
        </div>

        <div className="divide-y divide-slate-800/60">
          {feeds.map((feed) => {
            const isSyncing = isSyncingFeedId === feed.id || feed.status === 'SYNCING';
            return (
              <div key={feed.id} className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 hover:bg-slate-800/30 transition">
                <div className="space-y-1">
                  <div className="flex items-center space-x-2.5">
                    <span className="font-medium text-sm text-slate-200">{feed.name}</span>
                    <span className={`px-2 py-0.5 rounded text-[11px] font-mono border ${
                      feed.status === 'COMPLETED' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
                      feed.status === 'SYNCING' ? 'bg-sky-500/10 text-sky-400 border-sky-500/20 animate-pulse' :
                      feed.status === 'ERROR' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                      'bg-slate-800 text-slate-300 border-slate-700'
                    }`}>
                      {feed.status}
                    </span>
                    <span className="text-xs font-mono text-slate-500">{feed.feedType} ({feed.format})</span>
                  </div>
                  <p className="text-xs text-slate-400 font-mono break-all">{feed.feedUrl}</p>
                </div>

                <div className="flex items-center space-x-4 self-end md:self-auto font-mono text-xs">
                  <div className="text-right">
                    <div className="text-slate-300 font-semibold">{feed.itemCount} items</div>
                    <div className="text-[11px] text-slate-500">
                      {feed.lastFetchedAt ? new Date(feed.lastFetchedAt).toLocaleTimeString() : 'Never'}
                    </div>
                  </div>

                  {canManage && (
                    <button
                      onClick={() => handleSyncFeed(feed.id)}
                      disabled={isSyncing}
                      className="flex items-center space-x-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-medium transition disabled:opacity-50"
                    >
                      <RefreshCw className={`w-3 h-3 ${isSyncing ? 'animate-spin' : ''}`} />
                      <span>{isSyncing ? 'Syncing...' : 'Sync Feed'}</span>
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* IOC Search & Filters */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search IP, Domain, Hash, URL, Tag..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 text-xs placeholder-slate-500 focus:outline-none focus:border-emerald-500"
          />
        </div>

        <div className="flex items-center space-x-2">
          <Filter className="w-4 h-4 text-slate-400" />
          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-300 text-xs focus:outline-none focus:border-emerald-500"
          >
            <option value="ALL">All Types</option>
            <option value="IP">IP Address</option>
            <option value="DOMAIN">Domain</option>
            <option value="URL">URL</option>
            <option value="HASH_SHA256">SHA256</option>
            <option value="HASH_MD5">MD5</option>
            <option value="EMAIL">Email</option>
          </select>

          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-300 text-xs focus:outline-none focus:border-emerald-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {/* IOC Table */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/80 text-slate-400 font-mono text-[11px]">
                <th className="px-4 py-3">TYPE</th>
                <th className="px-4 py-3">INDICATOR VALUE</th>
                <th className="px-4 py-3">SEVERITY</th>
                <th className="px-4 py-3">CONFIDENCE</th>
                <th className="px-4 py-3">MITRE ATT&CK</th>
                <th className="px-4 py-3">SOURCE</th>
                <th className="px-4 py-3 text-right">ACTIONS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {iocs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-slate-500">
                    No matching indicators found. Try adjusting filters or syncing threat feeds.
                  </td>
                </tr>
              ) : (
                iocs.map((ioc) => (
                  <tr key={ioc.id} className="hover:bg-slate-800/40 transition">
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${getTypeBadge(ioc.type)}`}>
                        {ioc.type}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center space-x-2">
                        <span className="font-semibold text-slate-200 select-all">{ioc.value}</span>
                        <button
                          onClick={() => copyToClipboard(ioc.value, ioc.id)}
                          className="text-slate-500 hover:text-slate-300 transition"
                          title="Copy indicator"
                        >
                          {copiedId === ioc.id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                      {ioc.description && (
                        <p className="text-[11px] text-slate-400 font-sans mt-0.5 line-clamp-1">{ioc.description}</p>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${getSeverityBadge(ioc.severity || 'MEDIUM')}`}>
                        {ioc.severity || 'MEDIUM'}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center space-x-2">
                        <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-emerald-500 rounded-full"
                            style={{ width: `${Math.round((ioc.confidence || 0.8) * 100)}%` }}
                          />
                        </div>
                        <span className="text-[11px] text-slate-400">
                          {Math.round((ioc.confidence || 0.8) * 100)}%
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      {ioc.mitreTechniques && ioc.mitreTechniques.length > 0 ? (
                        <span className="px-2 py-0.5 rounded text-[10px] bg-purple-500/10 text-purple-300 border border-purple-500/20">
                          {ioc.mitreTechniques.join(', ')}
                        </span>
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-slate-400 font-sans text-xs">
                      {ioc.source || 'MANUAL'}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {canManage && (
                        <button
                          onClick={() => handleDeleteIoc(ioc.id)}
                          className="p-1 rounded hover:bg-red-500/10 text-slate-500 hover:text-red-400 transition"
                          title="Delete indicator"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add IOC Modal */}
      {isAddModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Plus className="w-5 h-5 text-emerald-400" />
                <h3 className="font-bold text-base text-white">Add Indicator of Compromise</h3>
              </div>
              <button
                onClick={() => setIsAddModalOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            {modalError && (
              <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs">
                {modalError}
              </div>
            )}

            <form onSubmit={handleCreateIoc} className="space-y-4 text-xs font-sans">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1 font-mono">IOC Type</label>
                  <select
                    value={newIoc.type}
                    onChange={(e) => setNewIoc({ ...newIoc, type: e.target.value as IOCType })}
                    className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-200"
                  >
                    <option value="IP">IP Address</option>
                    <option value="DOMAIN">Domain</option>
                    <option value="URL">URL</option>
                    <option value="HASH_SHA256">File Hash (SHA256)</option>
                    <option value="HASH_MD5">File Hash (MD5)</option>
                    <option value="EMAIL">Email Address</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1 font-mono">Severity</label>
                  <select
                    value={newIoc.severity}
                    onChange={(e) => setNewIoc({ ...newIoc, severity: e.target.value as AlertSeverity })}
                    className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-200"
                  >
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-mono">Indicator Value *</label>
                <input
                  type="text"
                  required
                  placeholder={newIoc.type === 'IP' ? '198.51.100.45' : newIoc.type === 'DOMAIN' ? 'c2-beacon.domain.com' : 'Value...'}
                  value={newIoc.value}
                  onChange={(e) => setNewIoc({ ...newIoc, value: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-200 font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1 font-mono">Confidence ({Math.round(newIoc.confidence * 100)}%)</label>
                  <input
                    type="range"
                    min="0.1"
                    max="1.0"
                    step="0.05"
                    value={newIoc.confidence}
                    onChange={(e) => setNewIoc({ ...newIoc, confidence: parseFloat(e.target.value) })}
                    className="w-full accent-emerald-500"
                  />
                </div>

                <div>
                  <label className="block text-slate-400 mb-1 font-mono">MITRE Technique ID</label>
                  <input
                    type="text"
                    placeholder="e.g. T1071.001"
                    value={newIoc.mitreTechniques}
                    onChange={(e) => setNewIoc({ ...newIoc, mitreTechniques: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-200 font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-mono">Description / Context</label>
                <input
                  type="text"
                  placeholder="Suspected Cobalt Strike beacon infrastructure"
                  value={newIoc.description}
                  onChange={(e) => setNewIoc({ ...newIoc, description: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-200"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-mono">Tags (comma-separated)</label>
                <input
                  type="text"
                  placeholder="c2, cobalt-strike, apt29"
                  value={newIoc.tags}
                  onChange={(e) => setNewIoc({ ...newIoc, tags: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-200 font-mono"
                />
              </div>

              <div className="flex items-center justify-end space-x-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsAddModalOpen(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold transition"
                >
                  {isSubmitting ? 'Saving...' : 'Save Indicator'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
