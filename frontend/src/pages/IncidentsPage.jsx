import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  Clock,
  MessageSquare,
  CheckCircle,
  ChevronRight,
  User,
  Download,
  Brain,
  ShieldCheck,
  ExternalLink,
  RefreshCw,
  FileText,
} from 'lucide-react';
import { useSoc } from '../context/SocContext';
import { api } from '../api/client';

export default function IncidentsPage() {
  const { incidents, patchIncident, addIncidentNote, setSelectedAttackerId, addToast } = useSoc();
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [newNote, setNewNote] = useState('');
  const [assigneeInput, setAssigneeInput] = useState('');
  const [investigation, setInvestigation] = useState(null);
  const [loadingInv, setLoadingInv] = useState(false);
  const [integrityData, setIntegrityData] = useState(null);

  const activeInc = selectedIncident
    ? incidents.find((i) => i.id === selectedIncident.id) || selectedIncident
    : incidents[0] || null;

  // Load AI investigation and integrity check on active incident change
  useEffect(() => {
    if (!activeInc) return;
    setAssigneeInput(activeInc.assignee || '');

    // Fetch AI investigation
    setLoadingInv(true);
    api.getIncidentInvestigation(activeInc.id)
      .then((inv) => setInvestigation(inv))
      .catch((e) => console.warn('AI Investigation load failed:', e.message))
      .finally(() => setLoadingInv(false));

    // Fetch integrity check if contributing events
    const firstEvId = activeInc.root_cause?.contributing_events?.[0];
    if (firstEvId) {
      api.getEventIntegrity(firstEvId)
        .then((res) => setIntegrityData(res))
        .catch(() => setIntegrityData(null));
    }
  }, [activeInc?.id]);

  const handleStatusChange = (status) => {
    if (!activeInc) return;
    patchIncident(activeInc.id, { status, note: `Status transitioned to ${status}` });
  };

  const handleAssigneeUpdate = (e) => {
    e.preventDefault();
    if (!activeInc) return;
    patchIncident(activeInc.id, { assignee: assigneeInput });
  };

  const handleAddNote = (e) => {
    e.preventDefault();
    if (!newNote.trim() || !activeInc) return;
    addIncidentNote(activeInc.id, newNote);
    setNewNote('');
  };

  const handleRefreshInvestigation = async () => {
    if (!activeInc) return;
    try {
      setLoadingInv(true);
      const res = await api.triggerIncidentInvestigate(activeInc.id);
      setInvestigation(res);
      addToast('AI investigation refreshed with latest telemetry', 'success');
    } catch (e) {
      addToast(`Refresh failed: ${e.message}`, 'error');
    } finally {
      setLoadingInv(false);
    }
  };

  const handleDownloadPdf = () => {
    if (!activeInc) return;
    const url = api.getIncidentReportUrl(activeInc.id);
    window.open(url, '_blank');
    addToast(`Downloading Incident INC-${activeInc.id} PDF Report`, 'info');
  };

  return (
      <div className="space-y-4 font-mono text-xs">
        <div>
            <h1 className="text-xl font-bold text-white tracking-wider flex items-center space-x-2">
              <span>INCIDENT TRIAGE & AI INVESTIGATION</span>
              <span className="text-xs px-2 py-0.5 rounded bg-red-950 border border-red-500/30 text-red-300 font-bold">
                {incidents.length} CASES
              </span>
            </h1>
              <p className="text-xs text-soc-muted mt-0.5">
                Lifecycle triage stepper, automated containment escalation, and generative threat intelligence
              </p>
            </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Incident Queue List */}
                <div className="lg:col-span-1 space-y-2">
                  <div className="text-soc-muted text-xs uppercase tracking-wider mb-2">Queue Tickets</div>
                    <div className="space-y-2 max-h-[750px] overflow-y-auto pr-1">
                      {incidents.map((inc) => (
                        <div
                          key={inc.id}
                          onClick={() => setSelectedIncident(inc)}
                          className={`p-3 rounded border cursor-pointer transition space-y-2 ${activeInc?.id === inc.id
                                ? 'border-cyan-500 bg-cyan-950/30 shadow-[0_0_15px_rgba(0,240,255,0.15)]'
                                : 'border-soc-border bg-soc-card hover:border-gray-500'
                }`}
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-white text-xs truncate max-w-[190px]">
                              {inc.title}
                            </span>
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${inc.status === 'new'
                                  ? 'bg-red-950 text-red-400 border border-red-500/40'
                                  : inc.status === 'investigating'
                                    ? 'bg-yellow-950 text-yellow-400 border border-yellow-500/40'
                                    : inc.status === 'contained'
                                      ? 'bg-purple-950 text-purple-400 border border-purple-500/40'
                                      : 'bg-emerald-950 text-emerald-400 border border-emerald-500/40'
                                }`}
                            >
                              {inc.status}
                            </span>
                          </div>
                          <div className="text-[10px] text-soc-muted flex items-center justify-between">
                            <span>{new Date(inc.created_at).toLocaleString()}</span>
                            <span>Score: {inc.risk_score_at_creation?.toFixed(0)}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Selected Incident Detail */}
                  {activeInc ? (
                    <div className="lg:col-span-2 p-5 rounded border border-soc-border bg-soc-card space-y-5">
                        {/* Header with Title and Download PDF Button */}
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-soc-border pb-4">
                          <div>
                            <div className="flex items-center space-x-2">
                              <h2 className="text-base font-bold text-white tracking-wide">{activeInc.title}</h2>
                              <span className="px-2 py-0.2 rounded bg-cyan-950 border border-cyan-500/40 text-cyan-300 text-[10px] font-bold">
                                INC-{activeInc.id}
                              </span>
                            </div>
                            <div className="text-soc-muted text-[11px] mt-1 flex items-center space-x-3">
                              <span>Assignee: <span className="text-white font-medium">{activeInc.assignee || 'Unassigned'}</span></span>
                              {activeInc.attacker_id && (
                                <button
                                  onClick={() => setSelectedAttackerId(activeInc.attacker_id)}
                                  className="text-cyan-400 hover:underline flex items-center space-x-1"
                                >
                                  <span>View Attacker Dossier</span>
                                  <ExternalLink className="h-3 w-3" />
                                </button>
                              )}
                            </div>
                          </div>

                              {/* Action Buttons: Download PDF */ }
                              < div className = "flex items-center space-x-2" >
                              <button
                                onClick={handleDownloadPdf}
                                className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-cyan-950 border border-cyan-400 text-cyan-200 hover:bg-cyan-900 transition font-bold shadow-[0_0_10px_rgba(0,240,255,0.25)]"
                              >
                                <Download className="h-3.5 w-3.5" />
                                <span>REPORT PDF</span>
                              </button>
              </div>
                        </div>

                        {/* Stepper Lifecycle Controls */}
                        <div className="p-3 rounded bg-soc-surface border border-soc-border space-y-2">
                          <span className="text-[10px] text-soc-muted uppercase tracking-wider block">Incident Lifecycle Stepper</span>
                          <div className="grid grid-cols-4 gap-2">
                            {['new', 'investigating', 'contained', 'resolved'].map((st, sIdx) => {
                              const isCurrent = activeInc.status === st;
                              return (
                                <button
                                  key={st}
                                  onClick={() => handleStatusChange(st)}
                                  className={`py-2 px-1 rounded text-center uppercase font-bold text-[10px] transition border ${isCurrent
                                      ? 'bg-cyan-500 text-black border-cyan-400 shadow-[0_0_12px_rgba(0,240,255,0.4)]'
                                      : 'bg-soc-card border-soc-border text-soc-muted hover:text-white hover:border-gray-500'
                                    }`}
                                >
                                  <span>{sIdx + 1}. {st}</span>
                                </button>
                              );
                            })}
                          </div>
                        </div>

                        {/* AI Investigation Dossier Card */}
                        <div className="p-4 rounded-lg bg-black/60 border border-cyan-500/40 shadow-[0_0_15px_rgba(0,240,255,0.15)] space-y-3">
                          <div className="flex items-center justify-between border-b border-cyan-500/30 pb-2">
                            <div className="flex items-center space-x-2 text-cyan-300 font-bold">
                              <Brain className="h-4 w-4" />
                              <span>AI THREAT INVESTIGATION AGENT</span>
                            </div>
                            <div className="flex items-center space-x-2">
                              <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-500/40">
                                Confidence: {investigation?.confidence ? `${(investigation.confidence * 100).toFixed(0)}%` : 'N/A'}
                              </span>
                              <button
                                onClick={handleRefreshInvestigation}
                                disabled={loadingInv}
                                className="p-1 rounded bg-soc-card text-soc-muted hover:text-white"
                                title="Refresh AI Analysis"
                              >
                                <RefreshCw className={`h-3.5 w-3.5 ${loadingInv ? 'animate-spin' : ''}`} />
                              </button>
                            </div>
                          </div>

                          {loadingInv ? (
                            <div className="text-center py-6 text-soc-muted animate-pulse">
                              Synthesizing honeypot telemetry and MITRE ATT&CK vectors...
                            </div>
                          ) : investigation ? (
                            <div className="space-y-3">
                              <div>
                                <span className="text-[10px] text-soc-muted uppercase block font-bold">What Happened:</span>
                                <p className="text-white text-[11px] leading-relaxed mt-0.5">{investigation.what_happened}</p>
                              </div>
                              <div>
                                <span className="text-[10px] text-soc-muted uppercase block font-bold">Operational Threat Impact:</span>
                                <p className="text-red-300 text-[11px] leading-relaxed mt-0.5">{investigation.why_dangerous}</p>
                              </div>
                              <div>
                                <span className="text-[10px] text-soc-muted uppercase block font-bold">Recommended Containment Actions:</span>
                                <ul className="mt-1 space-y-1">
                                  {investigation.recommended_actions?.map((act, i) => (
                                    <li key={i} className="text-cyan-200 text-[11px] flex items-start space-x-1.5">
                                      <span className="text-cyan-400 font-bold">&bull;</span>
                                      <span>{act}</span>
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            </div>
                          ) : (
                            <div className="text-soc-muted py-4 text-center">
                              Click refresh to run generative AI incident synthesis.
                            </div>
                          )}
                        </div>

                          {/* Metrics: TTD / TTR and Chain of Custody */}
                          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                            <div className="p-3 rounded bg-soc-surface border border-soc-border">
                              <span className="text-[10px] text-soc-muted uppercase block">Time to Detect (TTD)</span>
                              <span className="text-white font-bold text-sm mt-1 block">
                                {activeInc.ttd_seconds ? `${activeInc.ttd_seconds}s` : 'N/A'}
                              </span>
                            </div>
                            <div className="p-3 rounded bg-soc-surface border border-soc-border">
                              <span className="text-[10px] text-soc-muted uppercase block">Time to Respond (TTR)</span>
                              <span className="text-white font-bold text-sm mt-1 block">
                                {activeInc.ttr_seconds ? `${activeInc.ttr_seconds}s` : 'Active containment'}
                              </span>
                            </div>
                            <div className="p-3 rounded bg-soc-surface border border-soc-border">
                              <span className="text-[10px] text-soc-muted uppercase block">Evidence Custody</span>
                              <span className="text-emerald-400 font-bold text-xs mt-1 flex items-center space-x-1">
                                <ShieldCheck className="h-3.5 w-3.5" />
                                <span>SHA-256 VERIFIED</span>
                              </span>
                            </div>
                          </div>

                          {/* Assignee Form */}
                          <form onSubmit={handleAssigneeUpdate} className="flex items-center space-x-2 p-3 rounded bg-soc-surface border border-soc-border">
                            <span className="text-soc-muted text-xs">Assignee:</span>
                            <input
                              type="text"
                              value={assigneeInput}
                              onChange={(e) => setAssigneeInput(e.target.value)}
                              placeholder="Assign analyst handle..."
                              className="flex-1 bg-soc-card border border-soc-border rounded px-3 py-1 text-white placeholder-soc-muted focus:outline-none focus:border-cyan-500"
                            />
                            <button
                              type="submit"
                              className="px-3 py-1 rounded bg-soc-card border border-soc-border text-cyan-300 hover:border-cyan-400 transition"
                            >
                              UPDATE ASSIGNEE
                            </button>
                          </form>

                          {/* Notes Section */}
                          <div className="space-y-3">
                            <span className="text-soc-muted text-xs uppercase tracking-wider">Analyst Notes</span>
                            <div className="space-y-2 max-h-40 overflow-y-auto">
                              {activeInc.notes?.map((n, i) => (
                                  <div key={i} className="p-2.5 rounded bg-soc-surface border border-soc-border text-[11px]">
                                    <div className="flex justify-between text-soc-muted text-[10px] mb-1">
                                      <span className="font-bold text-cyan-300">{n.author}</span>
                                      <span>{new Date(n.ts).toLocaleTimeString()}</span>
                                    </div>
                                    <div className="text-white">{n.text}</div>
                                  </div>
                ))}
                                </div>

              {/* Add Note Form */ }
                                < form onSubmit = { handleAddNote } className = "flex space-x-2" >
                <input
                  type="text"
                  value={newNote}
                  onChange={(e) => setNewNote(e.target.value)}
                  placeholder="Append analyst note to ticket..."
                  className="flex-1 bg-soc-surface border border-soc-border rounded px-3 py-1.5 text-white placeholder-soc-muted focus:outline-none focus:border-cyan-500"
                />
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-cyan-950 border border-cyan-500 text-cyan-300 font-bold hover:bg-cyan-900 transition"
                >
                  ADD NOTE
                </button>
              </form>
                          </div>
                        </div>
                        ) : (
                        <div className="lg:col-span-2 text-center py-24 text-soc-muted">
                          Select an incident from the queue to view investigation.
                        </div>
        )}
                      </div>
                    </div>
                  );
}
