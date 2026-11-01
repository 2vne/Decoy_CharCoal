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
  PhoneCall,
  Mail,
  Radio,
  Check,
  CheckCircle2,
  AlertOctagon,
  Activity,
  ShieldAlert,
  Bell,
  Layers,
  Send,
} from 'lucide-react';
import { useSoc } from '../context/SocContext';
import { api } from '../api/client';
import RemediationAdvisorCard from '../components/RemediationAdvisorCard';

export default function IncidentsPage() {
  const {
    incidents,
    patchIncident,
    addIncidentNote,
    setSelectedAttackerId,
    addToast,
    pagerdutyIncidents,
    pagerdutyStatus,
    refreshPagerdutyData,
    triggerPagerDutyTest,
    ackPagerDutyIncident,
    resolvePagerDutyIncident,
  } = useSoc();

  const [activeTab, setActiveTab] = useState('pagerduty'); // 'triage' | 'pagerduty'
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [newNote, setNewNote] = useState('');
  const [assigneeInput, setAssigneeInput] = useState('');
  const [investigation, setInvestigation] = useState(null);
  const [loadingInv, setLoadingInv] = useState(false);
  const [integrityData, setIntegrityData] = useState(null);

  // PagerDuty tab state
  const [selectedPdIncident, setSelectedPdIncident] = useState(null);
  const [testAlertLoading, setTestAlertLoading] = useState(false);
  const [actionLoadingKey, setActionLoadingKey] = useState(null);

  const activeInc = selectedIncident
    ? incidents.find((i) => i.id === selectedIncident.id) || selectedIncident
    : incidents[0] || null;

  const activePd = selectedPdIncident
    ? pagerdutyIncidents.find((i) => i.dedup_key === selectedPdIncident.dedup_key) || selectedPdIncident
    : pagerdutyIncidents[0] || null;

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
    patchIncident(activeInc.id, { assignee: assigneeInput, note: `Assigned to ${assigneeInput}` });
  };

  const handleAddNote = (e) => {
    e.preventDefault();
    if (!newNote.trim() || !activeInc) return;
    addIncidentNote(activeInc.id, newNote);
    setNewNote('');
  };

  const handleTriggerInvestigation = async () => {
    if (!activeInc) return;
    setLoadingInv(true);
    try {
      const inv = await api.triggerIncidentInvestigation(activeInc.id);
      setInvestigation(inv);
      addToast('AI Investigation analysis complete', 'success');
    } catch (e) {
      addToast(`Investigation failed: ${e.message}`, 'error');
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

  const handleRunPdTest = async () => {
    setTestAlertLoading(true);
    try {
      await triggerPagerDutyTest('soc_analyst');
    } catch (e) {
      console.error(e);
    } finally {
      setTestAlertLoading(false);
    }
  };

  const handleAckPd = async (dedupKey) => {
    setActionLoadingKey(`ack_${dedupKey}`);
    try {
      await ackPagerDutyIncident(dedupKey);
    } catch (e) {
      console.error(e);
    } finally {
      setActionLoadingKey(null);
    }
  };

  const handleResolvePd = async (dedupKey) => {
    setActionLoadingKey(`res_${dedupKey}`);
    try {
      await resolvePagerDutyIncident(dedupKey, 'soc_operator', 'Manual resolution from SOC Dashboard');
    } catch (e) {
      console.error(e);
    } finally {
      setActionLoadingKey(null);
    }
  };

  const openPdCount = pagerdutyIncidents.filter((i) => i.status !== 'resolved').length;
  const p1PdCount = pagerdutyIncidents.filter((i) => i.priority === 'P1' && i.status !== 'resolved').length;

  return (
    <div className="space-y-4 font-mono text-xs">
      {/* Top Header & Tab Switcher */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-soc-border pb-3">
        <div>
          <h1 className="text-xl font-bold text-white tracking-wider flex items-center space-x-2">
            <span>INCIDENT COMMAND & ON-CALL RESPONSE</span>
            {p1PdCount > 0 && (
              <span className="text-[10px] px-2 py-0.5 rounded bg-red-950 border border-red-500 text-red-300 font-bold animate-pulse flex items-center space-x-1">
                <AlertOctagon className="h-3 w-3 inline mr-1" />
                {p1PdCount} CRITICAL P1 ALERT{p1PdCount > 1 ? 'S' : ''}
              </span>
            )}
          </h1>
          <p className="text-xs text-soc-muted mt-0.5">
            Real-time incident correlation, deduplicated PagerDuty on-call dispatch, and automated severity escalation
          </p>
        </div>

        {/* Tab Buttons */}
        <div className="flex items-center space-x-2 bg-soc-surface p-1 rounded border border-soc-border">
          <button
            onClick={() => setActiveTab('pagerduty')}
            className={`px-3 py-1.5 rounded font-bold text-xs flex items-center space-x-1.5 transition ${
              activeTab === 'pagerduty'
                ? 'bg-rose-950/60 text-rose-300 border border-rose-800'
                : 'text-soc-muted hover:text-white'
            }`}
          >
            <Bell className="h-3.5 w-3.5" />
            <span>PAGERDUTY ON-CALL</span>
            {openPdCount > 0 && (
              <span className="ml-1 px-1.5 py-0.2 text-[10px] rounded-full bg-rose-600 text-white font-extrabold">
                {openPdCount}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('triage')}
            className={`px-3 py-1.5 rounded font-bold text-xs flex items-center space-x-1.5 transition ${
              activeTab === 'triage'
                ? 'bg-slate-800 text-slate-100 border border-slate-700'
                : 'text-soc-muted hover:text-white'
            }`}
          >
            <Brain className="h-3.5 w-3.5" />
            <span>INCIDENT TRIAGE & AI</span>
            <span className="ml-1 px-1.5 py-0.2 text-[10px] rounded-full bg-soc-border text-soc-muted font-bold">
              {incidents.length}
            </span>
          </button>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: PAGERDUTY ON-CALL INTEGRATION VIEW                                 */}
      {/* ========================================================================= */}
      {activeTab === 'pagerduty' && (
        <div className="space-y-4">
          {/* Status & Responder Configuration Banner */}
          <div className="p-4 rounded border border-soc-border bg-soc-card shadow-sm space-y-3">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-soc-border/60 pb-3">
              <div className="flex items-center space-x-3">
                <div className={`p-2 rounded border ${
                  pagerdutyStatus?.service_mode === 'operational'
                    ? 'bg-emerald-950/60 border-emerald-500/40 text-emerald-400'
                    : 'bg-amber-950/60 border-amber-500/40 text-amber-400'
                }`}>
                  <Radio className="h-5 w-5 animate-pulse" />
                </div>
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="font-bold text-white text-sm tracking-wide">PAGERDUTY EVENTS API v2 INTEGRATION</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      pagerdutyStatus?.service_mode === 'operational'
                        ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/40'
                        : 'bg-amber-950 text-amber-300 border border-amber-500/40'
                    }`}>
                      {pagerdutyStatus?.service_mode === 'operational' ? 'LIVE OPERATIONAL' : 'LOCAL SIMULATED ACTIVE'}
                    </span>
                  </div>
                  <div className="text-[11px] text-soc-muted mt-0.5">
                    Endpoint: <span className="text-gray-300">https://events.pagerduty.com/v2/enqueue</span> &bull; Key:{' '}
                    <span className="text-cyan-400">{pagerdutyStatus?.routing_key_preview || 'Configured'}</span>
                  </div>
                </div>
              </div>

              {/* Action: Automated Real-Time Dispatch Status & Refresh */}
              <div className="flex items-center space-x-2">
                <div
                  className="px-3 py-1.5 rounded bg-emerald-950/60 border border-emerald-800 text-emerald-300 font-mono text-xs flex items-center space-x-2"
                  title="Autonomous alert dispatch is active. PagerDuty, Resend Email, and Voice Call alerts are triggered automatically whenever an attack is detected."
                >
                  <span className="relative flex h-2 w-2">
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-400"></span>
                  </span>
                  <span className="font-semibold tracking-wider text-[11px]">AUTONOMOUS ATTACK DISPATCH: ACTIVE</span>
                </div>
                <button
                  onClick={refreshPagerdutyData}
                  className="p-1.5 rounded bg-soc-surface border border-soc-border text-soc-muted hover:text-white transition"
                  title="Refresh PagerDuty state"
                >
                  <RefreshCw className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>

            {/* Configured Responders Card Grid */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-[11px]">
              <div className="p-2.5 rounded bg-soc-surface border border-soc-border">
                <div className="text-soc-muted text-[10px] uppercase flex items-center space-x-1 mb-1">
                  <PhoneCall className="h-3 w-3 text-emerald-400" />
                  <span>On-Call Voice Target</span>
                </div>
                <div className="font-bold text-white tracking-wide">
                  +91 {pagerdutyStatus?.responder_phone || '9372185727'}
                </div>
                <div className="text-[10px] text-emerald-400 mt-0.5">High-priority voice call escalation</div>
              </div>

              <div className="p-2.5 rounded bg-soc-surface border border-soc-border">
                <div className="text-soc-muted text-[10px] uppercase flex items-center space-x-1 mb-1">
                  <Mail className="h-3 w-3 text-cyan-400" />
                  <span>Authority Email Alert</span>
                </div>
                <div className="font-bold text-white truncate">
                  {pagerdutyStatus?.responder_email || 'danishsjain@gmail.com'}
                </div>
                <div className="text-[10px] text-cyan-400 mt-0.5">Incident report delivery</div>
              </div>

              <div className="p-2.5 rounded bg-soc-surface border border-soc-border">
                <div className="text-soc-muted text-[10px] uppercase flex items-center space-x-1 mb-1">
                  <Layers className="h-3 w-3 text-purple-400" />
                  <span>Correlation Deduplication</span>
                </div>
                <div className="font-bold text-white">Session-Grouped (dedup_key)</div>
                <div className="text-[10px] text-purple-400 mt-0.5">Zero incident flooding</div>
              </div>

              <div className="p-2.5 rounded bg-soc-surface border border-soc-border">
                <div className="text-soc-muted text-[10px] uppercase flex items-center space-x-1 mb-1">
                  <Activity className="h-3 w-3 text-amber-400" />
                  <span>Active Incident Queue</span>
                </div>
                <div className="font-bold text-white flex items-center space-x-2">
                  <span>{openPdCount} OPEN</span>
                  {p1PdCount > 0 && <span className="text-red-400 font-bold">({p1PdCount} P1 Critical)</span>}
                </div>
                <div className="text-[10px] text-soc-muted mt-0.5">
                  Last event: {pagerdutyStatus?.last_event_ts ? new Date(pagerdutyStatus.last_event_ts).toLocaleTimeString() : 'Ready'}
                </div>
              </div>
            </div>
          </div>

          {/* Incidents Queue & Details Split Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Left Column: PagerDuty Incidents List */}
            <div className="lg:col-span-1 space-y-2">
              <div className="flex items-center justify-between text-soc-muted text-xs uppercase tracking-wider mb-1">
                <span>Correlated Tickets ({pagerdutyIncidents.length})</span>
                <span className="text-[10px] text-cyan-400">Auto-Escalating</span>
              </div>

              <div className="space-y-2 max-h-[650px] overflow-y-auto pr-1">
                {pagerdutyIncidents.length === 0 ? (
                  <div className="p-6 text-center text-soc-muted border border-dashed border-soc-border rounded">
                    No PagerDuty incidents registered yet.
                    <div className="text-[11px] text-soc-muted mt-2">
                      Incidents trigger automatically on decoy honeytoken access, payment tampering, or attack simulation.
                    </div>
                  </div>
                ) : (
                  pagerdutyIncidents.map((inc) => {
                    const isSelected = activePd?.dedup_key === inc.dedup_key;
                    const isP1 = inc.priority === 'P1';
                    const isP2 = inc.priority === 'P2';
                    const isTriggered = inc.status === 'triggered';

                    return (
                      <div
                        key={inc.dedup_key}
                        onClick={() => setSelectedPdIncident(inc)}
                        className={`p-3 rounded border cursor-pointer transition space-y-2 ${
                          isSelected
                            ? isP1
                              ? 'border-rose-500 bg-rose-950/40 text-white'
                              : 'border-slate-500 bg-slate-800/80 text-white'
                            : 'border-slate-800 bg-slate-900/60 hover:border-slate-700'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-1.5">
                            <span
                              className={`px-1.5 py-0.5 rounded text-[10px] font-extrabold uppercase ${
                                isP1
                                  ? 'bg-red-950 text-red-400 border border-red-500/50'
                                  : isP2
                                  ? 'bg-amber-950 text-amber-400 border border-amber-500/50'
                                  : 'bg-blue-950 text-blue-400 border border-blue-500/50'
                              }`}
                            >
                              {inc.priority || 'P2'}
                            </span>
                            {inc.is_simulated && (
                              <span className="px-1 py-0.2 rounded text-[9px] bg-purple-950 text-purple-300 border border-purple-500/40 font-bold">
                                SIMULATED
                              </span>
                            )}
                          </div>

                          <span
                            className={`px-2 py-0.5 rounded text-[9px] uppercase font-bold ${
                              inc.status === 'triggered'
                                ? 'bg-red-950 text-red-300 border border-red-500/40 animate-pulse'
                                : inc.status === 'acknowledged'
                                ? 'bg-amber-950 text-amber-300 border border-amber-500/40'
                                : 'bg-emerald-950 text-emerald-300 border border-emerald-500/40'
                            }`}
                          >
                            {inc.status}
                          </span>
                        </div>

                        <div className="font-bold text-white text-xs truncate max-w-[260px]">
                          {inc.title}
                        </div>

                        <div className="flex items-center justify-between text-[10px] text-soc-muted">
                          <span className="truncate max-w-[150px] text-gray-400">
                            {inc.session_id ? `Sess: ${inc.session_id.slice(0, 14)}...` : inc.src_ip}
                          </span>
                          <span className="bg-soc-surface px-1.5 py-0.2 rounded border border-soc-border text-cyan-300 font-bold">
                            {inc.event_count || 1} event{(inc.event_count || 1) > 1 ? 's' : ''}
                          </span>
                        </div>

                        <div className="flex items-center justify-between text-[9px] text-soc-muted border-t border-soc-border/40 pt-1.5">
                          <span>{new Date(inc.created_at).toLocaleTimeString()}</span>
                          <span className="font-mono text-[9px] text-gray-400 truncate max-w-[120px]">
                            {inc.dedup_key}
                          </span>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>

            {/* Right Column: Active PagerDuty Incident Inspector */}
            <div className="lg:col-span-2">
              {activePd ? (
                <div className="p-4 rounded border border-soc-border bg-soc-card space-y-4">
                  {/* Incident Header */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-soc-border pb-3">
                    <div>
                      <div className="flex items-center space-x-2">
                        <span
                          className={`px-2 py-0.5 rounded font-extrabold text-[11px] uppercase ${
                            activePd.priority === 'P1'
                              ? 'bg-red-950 text-red-400 border border-red-500'
                              : 'bg-amber-950 text-amber-400 border border-amber-500'
                          }`}
                        >
                          {activePd.priority} - {activePd.severity?.toUpperCase()}
                        </span>
                        <h2 className="text-sm font-bold text-white tracking-wide">{activePd.title}</h2>
                      </div>
                      <div className="text-[10px] text-soc-muted mt-1 flex items-center space-x-3">
                        <span>Incident ID: <span className="text-white font-mono">{activePd.id}</span></span>
                        <span>Correlation Key: <span className="text-cyan-400 font-mono">{activePd.dedup_key}</span></span>
                      </div>
                    </div>

                    {/* Operational Action Buttons */}
                    <div className="flex items-center space-x-2">
                      {activePd.status === 'triggered' && (
                        <button
                          onClick={() => handleAckPd(activePd.dedup_key)}
                          disabled={actionLoadingKey === `ack_${activePd.dedup_key}`}
                          className="px-3 py-1.5 rounded bg-amber-950 border border-amber-500 text-amber-200 hover:bg-amber-900 font-bold transition flex items-center space-x-1"
                        >
                          <Check className="h-3 w-3" />
                          <span>ACKNOWLEDGE</span>
                        </button>
                      )}

                      {activePd.status !== 'resolved' && (
                        <button
                          onClick={() => handleResolvePd(activePd.dedup_key)}
                          disabled={actionLoadingKey === `res_${activePd.dedup_key}`}
                          className="px-3 py-1.5 rounded bg-emerald-950 border border-emerald-500 text-emerald-200 hover:bg-emerald-900 font-bold transition flex items-center space-x-1"
                        >
                          <CheckCircle2 className="h-3 w-3" />
                          <span>RESOLVE INCIDENT</span>
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Summary & Telemetry Metadata */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[10px]">
                    <div className="p-2 rounded bg-soc-surface border border-soc-border">
                      <div className="text-soc-muted uppercase">Session Identifier</div>
                      <div className="font-mono text-white truncate font-bold mt-0.5">{activePd.session_id}</div>
                    </div>
                    <div className="p-2 rounded bg-soc-surface border border-soc-border">
                      <div className="text-soc-muted uppercase">Attacker IP</div>
                      <div className="font-mono text-cyan-300 font-bold mt-0.5">{activePd.src_ip}</div>
                    </div>
                    <div className="p-2 rounded bg-soc-surface border border-soc-border">
                      <div className="text-soc-muted uppercase">Correlated Events</div>
                      <div className="font-bold text-white mt-0.5">{activePd.event_count || 1} grouped actions</div>
                    </div>
                    <div className="p-2 rounded bg-soc-surface border border-soc-border">
                      <div className="text-soc-muted uppercase">Delivery Status</div>
                      <div className="font-bold text-emerald-400 uppercase mt-0.5">{activePd.delivery_status || 'Delivered'}</div>
                    </div>
                  </div>

                  {/* Custom Details & Payload Snapshot */}
                  <div className="space-y-2">
                    <span className="text-[10px] text-soc-muted uppercase tracking-wider block">Incident Payload & Custom Details</span>
                    <pre className="p-3 rounded bg-soc-surface border border-soc-border text-gray-300 font-mono text-[10px] overflow-x-auto max-h-48">
                      {JSON.stringify(activePd.details || {}, null, 2)}
                    </pre>
                  </div>

                  {/* Breadcrumb Correlation History */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-[10px] text-soc-muted uppercase tracking-wider">
                      <span>Correlated Event Breadcrumbs ({activePd.history?.length || 0})</span>
                      <span className="text-emerald-400 font-normal">Unified under single PagerDuty ticket</span>
                    </div>

                    <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
                      {activePd.history?.map((h, idx) => (
                        <div
                          key={idx}
                          className="p-2 rounded bg-soc-surface border border-soc-border/70 text-[10px] flex items-start justify-between space-x-2"
                        >
                          <div className="space-y-0.5">
                            <div className="flex items-center space-x-1.5">
                              <span className="text-cyan-400 font-bold uppercase">{h.action}</span>
                              <span className="text-soc-muted">&bull;</span>
                              <span className="text-white font-medium">{h.summary || h.reason || h.by}</span>
                            </div>
                            {h.details?.endpoint && (
                              <div className="text-[9px] text-gray-400">
                                Path: <span className="text-amber-300">{h.details.endpoint}</span> &bull; Category: {h.details.category}
                              </div>
                            )}
                          </div>
                          <span className="text-soc-muted text-[9px] whitespace-nowrap">
                            {new Date(h.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="p-16 text-center text-soc-muted border border-soc-border rounded bg-soc-card">
                  Select an incident from the queue to inspect correlation details and responder dispatch state.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: INCIDENT TRIAGE & AI INVESTIGATION VIEW (EXISTING PRESERVED)       */}
      {/* ========================================================================= */}
      {activeTab === 'triage' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Incident Queue List */}
          <div className="lg:col-span-1 space-y-2">
            <div className="text-soc-muted text-xs uppercase tracking-wider mb-2">Queue Tickets ({incidents.length})</div>
            <div className="space-y-2 max-h-[750px] overflow-y-auto pr-1">
              {incidents.map((inc) => (
                <div
                  key={inc.id}
                  onClick={() => setSelectedIncident(inc)}
                  className={`p-3 rounded border cursor-pointer transition space-y-2 ${
                    activeInc?.id === inc.id
                      ? 'border-slate-500 bg-slate-800/80 text-white'
                      : 'border-slate-800 bg-slate-900/60 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white text-xs truncate max-w-[190px]">
                      {inc.title}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${
                        inc.status === 'new'
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

                {/* Action Buttons: Download PDF */}
                <div className="flex items-center space-x-2">
                  <button
                    onClick={handleDownloadPdf}
                    className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-slate-800 border border-slate-700 text-slate-200 hover:text-white transition font-medium text-xs"
                  >
                    <Download className="h-3.5 w-3.5" />
                    <span>REPORT PDF</span>
                  </button>
                </div>
              </div>

              {/* Stepper Lifecycle Controls */}
              <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-2">
                <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Incident Lifecycle Stepper</span>
                <div className="grid grid-cols-4 gap-2">
                  {['new', 'investigating', 'contained', 'resolved'].map((st, sIdx) => {
                    const isCurrent = activeInc.status === st;
                    return (
                      <button
                        key={st}
                        onClick={() => handleStatusChange(st)}
                        className={`py-2 px-1 rounded text-center uppercase font-bold text-[10px] transition border ${
                          isCurrent
                            ? 'bg-slate-700 text-white border-slate-600'
                            : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white hover:border-slate-700'
                        }`}
                      >
                        <span>{sIdx + 1}. {st}</span>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Assignee Updater Form */}
              <form onSubmit={handleAssigneeUpdate} className="flex items-center space-x-2">
                <input
                  type="text"
                  value={assigneeInput}
                  onChange={(e) => setAssigneeInput(e.target.value)}
                  placeholder="Assign responder..."
                  className="bg-soc-surface border border-soc-border rounded px-3 py-1.5 text-white placeholder-soc-muted focus:outline-none focus:border-cyan-500 flex-1"
                />
                <button
                  type="submit"
                  className="px-3 py-1.5 rounded bg-cyan-950 border border-cyan-500 text-cyan-300 font-bold hover:bg-cyan-900 transition"
                >
                  ASSIGN
                </button>
              </form>

              {/* AI Threat Investigation Section */}
              <div className="p-4 rounded border border-soc-border bg-soc-surface space-y-3">
                <div className="flex items-center justify-between border-b border-soc-border pb-2">
                  <div className="flex items-center space-x-2 text-cyan-400 font-bold text-xs">
                    <Brain className="h-4 w-4" />
                    <span>GENERATIVE AI INVESTIGATION DOSSIER</span>
                  </div>
                  <button
                    onClick={handleTriggerInvestigation}
                    disabled={loadingInv}
                    className="flex items-center space-x-1 text-[11px] text-cyan-300 hover:text-white transition disabled:opacity-50"
                  >
                    <RefreshCw className={`h-3 w-3 ${loadingInv ? 'animate-spin' : ''}`} />
                    <span>{loadingInv ? 'Analyzing...' : 'Re-Run AI Analysis'}</span>
                  </button>
                </div>

                {investigation ? (
                  <div className="space-y-3 text-[11px]">
                    <div className="p-2.5 rounded bg-black/40 border border-soc-border/60 text-gray-300 leading-relaxed">
                      {investigation.executive_summary || investigation.summary || 'Summary unavailable'}
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div className="p-2.5 rounded bg-soc-card border border-soc-border space-y-1">
                        <span className="text-[10px] text-soc-muted uppercase block">Root Cause Analysis</span>
                        <div className="text-white font-medium">
                          {investigation.root_cause_analysis?.finding || 'Deception honeypot sensor engagement'}
                        </div>
                      </div>

                      <div className="p-2.5 rounded bg-soc-card border border-soc-border space-y-1">
                        <span className="text-[10px] text-soc-muted uppercase block">Blast Radius Assessment</span>
                        <div className="text-white font-medium">
                          {investigation.blast_radius_assessment?.scope || 'Contained to isolated deception environment'}
                        </div>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="text-soc-muted text-center py-4">
                    {loadingInv ? 'Generating AI Investigation Dossier...' : 'No AI investigation cached. Click Re-Run AI Analysis.'}
                  </div>
                )}
              </div>

              {/* REMEDIATION ADVISOR SECTION (STEP 7) */}
              <div id="advisory">
                <RemediationAdvisorCard
                  incidentId={activeInc.id}
                  onOpenEvent={(evId) => setSelectedAttackerId(activeInc.attacker_id)}
                />
              </div>

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

                {/* Add Note Form */}
                <form onSubmit={handleAddNote} className="flex space-x-2">
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
      )}
    </div>
  );
}
