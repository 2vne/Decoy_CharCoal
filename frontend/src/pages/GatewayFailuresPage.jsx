import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  GitCommit,
  CheckCircle,
  Clock,
  Send,
  ExternalLink,
  ShieldAlert,
  Server,
  RotateCcw,
  User,
  Users,
  Search,
  Code2,
} from 'lucide-react';
import { useSoc } from '../context/SocContext';
import { api } from '../api/client';

export default function GatewayFailuresPage() {
  const { addToast } = useSoc();
  const [incidents, setIncidents] = useState([]);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [commits, setCommits] = useState([]);
  const [loading, setLoading] = useState(true);
  const [correlating, setCorrelating] = useState(false);
  const [notifying, setNotifying] = useState(false);

  // Filter state
  const [statusFilter, setStatusFilter] = useState('all');

  const fetchIncidents = async () => {
    try {
      setLoading(true);
      const res = await api.getGatewayFailures({
        status: statusFilter !== 'all' ? statusFilter : undefined,
      });
      setIncidents(res.incidents || []);
      if (res.incidents && res.incidents.length > 0 && !selectedIncident) {
        setSelectedIncident(res.incidents[0]);
        loadCommitsForIncident(res.incidents[0]);
      }
    } catch (err) {
      console.error(err);
      addToast(`Failures fetch error: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  const loadCommitsForIncident = async (inc) => {
    try {
      const res = await api.getGitCommits({ incident_id: inc.id });
      setCommits(res.attributions || []);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, [statusFilter]);

  const handleSelectIncident = (inc) => {
    setSelectedIncident(inc);
    loadCommitsForIncident(inc);
  };

  const handleCorrelate = async () => {
    if (!selectedIncident) return;
    try {
      setCorrelating(true);
      const res = await api.correlateIncidentCommits({
        incident_id: selectedIncident.id,
        affected_endpoint: selectedIncident.endpoint,
        affected_function: selectedIncident.related_function,
      });
      addToast(`Correlated ${res.leads_found} Git commit leads`, 'info');
      loadCommitsForIncident(selectedIncident);
    } catch (err) {
      addToast(`Correlation error: ${err.message}`, 'error');
    } finally {
      setCorrelating(false);
    }
  };

  const handleNotifyTeam = async (attributionId) => {
    try {
      setNotifying(true);
      const res = await api.notifyTeamLead({
        attribution_id: attributionId,
        notes: 'Human SOC analyst verified and approved team triage dispatch.',
      });
      addToast(res.message, 'info');
    } catch (err) {
      addToast(`Dispatch error: ${err.message}`, 'error');
    } finally {
      setNotifying(false);
    }
  };

  const handleResolve = async (id) => {
    try {
      await api.resolveGatewayFailure(id);
      addToast(`Incident #${id} marked as resolved.`, 'info');
      fetchIncidents();
    } catch (err) {
      addToast(`Resolve error: ${err.message}`, 'error');
    }
  };

  return (
    <div className="space-y-6 font-mono">
      {/* Title Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-lg p-5">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-amber-950/60 border border-amber-500/40 rounded-lg text-amber-400">
              <AlertTriangle className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white tracking-wider flex items-center gap-2">
                GATEWAY FAILURE INTELLIGENCE & COMMIT ATTRIBUTION
                <span className="text-xs px-2 py-0.5 rounded bg-purple-950 border border-purple-500/40 text-purple-300">
                  PHASE 4 & 5
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-1">
                Monitors HTTP 502/503/504 errors, tracks failure recurrence, and correlates Git authoring timelines to assign
                investigation leads to responsible engineering teams (non-accusatory).
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={fetchIncidents}
            className="p-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 rounded text-xs transition-all"
            title="Refresh Incidents"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Main Two-Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Incidents List (1 col) */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3 flex flex-col">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
              <Server className="w-4 h-4 text-amber-400" />
              Gateway Incidents ({incidents.length})
            </h2>
            <div className="flex items-center space-x-1 text-xs">
              <button
                onClick={() => setStatusFilter('all')}
                className={`px-2 py-0.5 rounded ${statusFilter === 'all' ? 'bg-blue-600 text-white font-bold' : 'text-slate-400'}`}
              >
                All
              </button>
              <button
                onClick={() => setStatusFilter('recurring')}
                className={`px-2 py-0.5 rounded ${statusFilter === 'recurring' ? 'bg-red-700 text-white font-bold' : 'text-slate-400'}`}
              >
                Recurring
              </button>
            </div>
          </div>

          <div className="space-y-2 flex-1 overflow-y-auto max-h-[600px]">
            {incidents.length === 0 ? (
              <div className="text-center py-12 text-xs text-slate-500">
                No active gateway failure incidents detected.
              </div>
            ) : (
              incidents.map((inc) => {
                const isSelected = selectedIncident?.id === inc.id;
                const isRecurring = inc.recurrence_count > 1;
                return (
                  <div
                    key={inc.id}
                    onClick={() => handleSelectIncident(inc)}
                    className={`p-3 rounded border text-xs cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-slate-950 border-blue-500 shadow-md ring-1 ring-blue-500/50'
                        : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-200 truncate max-w-[180px]">{inc.endpoint}</span>
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                          isRecurring
                            ? 'bg-red-950 text-red-400 border border-red-500/50'
                            : 'bg-amber-950 text-amber-400 border border-amber-500/50'
                        }`}
                      >
                        {inc.error_code} {isRecurring ? `(x${inc.recurrence_count})` : ''}
                      </span>
                    </div>

                    <div className="mt-1 text-[11px] text-slate-400 truncate">
                      {inc.error_details || 'Upstream gateway failure'}
                    </div>

                    <div className="mt-2 pt-1.5 border-t border-slate-800/80 flex items-center justify-between text-[10px] text-slate-500">
                      <span>Status: <span className="font-bold text-slate-300 uppercase">{inc.status}</span></span>
                      <span>{inc.last_failure_ts ? new Date(inc.last_failure_ts).toLocaleTimeString() : 'now'}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: AI Investigation & GitHub Commit Correlation (2 cols) */}
        <div className="lg:col-span-2 space-y-6">
          {selectedIncident ? (
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-5">
              {/* Incident Header Details */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="text-base font-bold text-white">{selectedIncident.endpoint}</span>
                    <span className="px-2 py-0.5 rounded bg-red-950 text-red-400 text-xs font-bold border border-red-500/40">
                      HTTP {selectedIncident.error_code}
                    </span>
                    {selectedIncident.recurrence_count > 1 && (
                      <span className="px-2 py-0.5 rounded bg-purple-950 text-purple-300 text-xs font-bold border border-purple-500/40">
                        RECURRING ({selectedIncident.recurrence_count} cycles)
                      </span>
                    )}
                  </div>
                  <div className="text-xs text-slate-400 mt-1">
                    First failure: {selectedIncident.first_failure_ts ? new Date(selectedIncident.first_failure_ts).toLocaleString() : 'N/A'}
                  </div>
                </div>

                <div className="flex items-center space-x-2">
                  <button
                    onClick={handleCorrelate}
                    disabled={correlating}
                    className="px-3 py-1.5 bg-purple-900/60 hover:bg-purple-800 border border-purple-500/50 text-white rounded text-xs flex items-center gap-1.5 disabled:opacity-50"
                  >
                    <GitCommit className="w-3.5 h-3.5" />
                    <span>{correlating ? 'Correlating...' : 'Investigate Git Commits'}</span>
                  </button>
                  {selectedIncident.status !== 'resolved' && (
                    <button
                      onClick={() => handleResolve(selectedIncident.id)}
                      className="px-3 py-1.5 bg-emerald-950 hover:bg-emerald-900 border border-emerald-500/50 text-emerald-300 rounded text-xs flex items-center gap-1.5"
                    >
                      <CheckCircle className="w-3.5 h-3.5" />
                      <span>Mark Resolved</span>
                    </button>
                  )}
                </div>
              </div>

              {/* AI Root-Cause Investigation Card */}
              {selectedIncident.ai_investigation && (
                <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-3 text-xs">
                  <h3 className="font-bold text-blue-400 uppercase tracking-wider flex items-center gap-2">
                    <Code2 className="w-4 h-4" />
                    AI Root-Cause Investigation & Triage Guidance
                  </h3>

                  {/* 1. Observed Facts vs Hypotheses */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-2">
                    <div className="bg-slate-900/80 p-3 rounded border border-slate-800">
                      <div className="font-bold text-emerald-400 mb-1">Observed Telemetry Facts:</div>
                      <ul className="list-disc list-inside space-y-1 text-slate-300 text-[11px]">
                        {(selectedIncident.ai_investigation.observed_facts || []).map((fact, idx) => (
                          <li key={idx}>{fact}</li>
                        ))}
                      </ul>
                    </div>

                    <div className="bg-slate-900/80 p-3 rounded border border-slate-800">
                      <div className="font-bold text-amber-400 mb-1">AI-Generated Hypotheses:</div>
                      <ul className="list-disc list-inside space-y-1 text-slate-300 text-[11px]">
                        {(selectedIncident.ai_investigation.hypotheses || []).map((hyp, idx) => (
                          <li key={idx}>{hyp}</li>
                        ))}
                      </ul>
                    </div>
                  </div>

                  {/* 2. Recommended Action Steps */}
                  <div className="mt-2 pt-2 border-t border-slate-800/80">
                    <div className="font-bold text-purple-300 mb-1">Actionable Recommendations:</div>
                    <div className="space-y-1.5">
                      {(selectedIncident.ai_investigation.recommended_actions || []).map((rec, idx) => (
                        <div key={idx} className="bg-slate-900 p-2 rounded text-[11px] text-slate-300 flex items-start justify-between">
                          <span>• <span className="font-bold text-white">{rec.action}:</span> {rec.details}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* Correlated Git Commits & Team Ownership */}
              <div className="space-y-3">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                  <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                    <GitCommit className="w-4 h-4 text-purple-400" />
                    Correlated Git History & Team Attribution ({commits.length})
                  </h3>
                  <span className="text-[11px] text-slate-500">Non-accusatory timeline matching</span>
                </div>

                <div className="space-y-2.5">
                  {commits.length === 0 ? (
                    <div className="text-center py-6 text-xs text-slate-500 bg-slate-950 rounded border border-slate-800">
                      No commits correlated yet. Click &ldquo;Investigate Git Commits&rdquo; above to match local commit timelines.
                    </div>
                  ) : (
                    commits.map((c) => (
                      <div
                        key={c.id || c.commit_hash}
                        className="bg-slate-950 p-3.5 rounded-lg border border-slate-800 hover:border-slate-700 transition-all text-xs space-y-2"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-2">
                            <span className="font-bold text-purple-400">{c.short_hash || c.commit_hash?.slice(0, 8)}</span>
                            <span className="text-slate-300 font-bold">{c.commit_msg}</span>
                          </div>
                          <span className="px-2 py-0.5 rounded bg-blue-950 text-blue-300 text-[10px] font-bold border border-blue-500/40 uppercase">
                            Team: {c.assigned_team}
                          </span>
                        </div>

                        <div className="text-[11px] text-slate-400 flex items-center space-x-4">
                          <span>Author: <span className="text-slate-200">{c.author_name}</span></span>
                          <span>Timestamp: {c.commit_ts ? new Date(c.commit_ts).toLocaleString() : 'N/A'}</span>
                          <span>Confidence: {(c.confidence * 100).toFixed(0)}%</span>
                        </div>

                        <div className="text-[11px] text-slate-300 bg-slate-900/60 p-2 rounded border border-slate-850 italic">
                          &ldquo;{c.explanation}&rdquo;
                        </div>

                        <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between text-[11px]">
                          <span className="text-slate-500 truncate max-w-[350px]">
                            Changed: {(c.changed_files || []).join(', ')}
                          </span>
                          <button
                            onClick={() => handleNotifyTeam(c.id)}
                            disabled={notifying}
                            className="px-2.5 py-1 bg-purple-950 hover:bg-purple-900 text-purple-300 border border-purple-500/50 rounded text-[10px] font-bold flex items-center gap-1 transition-all"
                          >
                            <Send className="w-3 h-3" />
                            Dispatch Team Triage
                          </button>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-12 text-center text-xs text-slate-500">
              Select a gateway incident from the left to view root-cause analysis and commit attribution.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

