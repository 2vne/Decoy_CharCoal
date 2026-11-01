import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Radio,
  Server,
  Play,
  Loader2,
  ChevronRight,
  RefreshCw,
  Activity,
  ArrowUpRight,
  GitBranch,
  Eye,
  CheckCircle2,
  Lock,
  Clock,
  Filter,
  Layers,
  Terminal,
  Zap,
  Wrench,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
} from 'recharts';
import { useSoc } from '../context/SocContext';
import { api, BASE_URL } from '../api/client';
import ThreatUniverse from '../components/ThreatUniverse';

export default function Overview() {
  const navigate = useNavigate();
  const {
    loading,
    backendError,
    overview,
    attackers,
    honeypots,
    incidents,
    events,
    metrics,
    isLiveConnected,
    refreshAllData,
    runSimulation,
    setSelectedAttackerId,
    pagerdutyIncidents,
    pagerdutyStatus,
  } = useSoc();

  // Local state
  const [gatewayStats, setGatewayStats] = useState(null);
  const [advisorySummary, setAdvisorySummary] = useState(null);
  const [simLoading, setSimLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [currentTime, setCurrentTime] = useState(new Date().toUTCString());
  const [eventCategoryFilter, setEventCategoryFilter] = useState('ALL');
  const [showUniverseRadar, setShowUniverseRadar] = useState(false);

  // Live UTC Clock updater
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date().toUTCString());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Fetch gateway stats and playbook advisory summary
  const fetchAuxData = async () => {
    try {
      const [gw, adv] = await Promise.allSettled([
        api.getGatewayStats(),
        api.getAdvisorySummary(),
      ]);
      if (gw.status === 'fulfilled') setGatewayStats(gw.value);
      if (adv.status === 'fulfilled') setAdvisorySummary(adv.value);
    } catch (err) {
      console.warn('Failed to load aux stats:', err.message);
    }
  };

  useEffect(() => {
    fetchAuxData();
    const interval = setInterval(fetchAuxData, 15000);
    return () => clearInterval(interval);
  }, []);

  const handleManualRefresh = async () => {
    setRefreshing(true);
    await Promise.allSettled([refreshAllData(), fetchAuxData()]);
    setRefreshing(false);
  };

  const handleRunDemo = async () => {
    setSimLoading(true);
    try {
      await runSimulation('full_chain', 2.0);
    } finally {
      setSimLoading(false);
    }
  };

  // Derive KPI metrics strictly from actual backend data
  const activeIncidentsCount = useMemo(() => {
    const openDb = (incidents || []).filter((i) => i.status !== 'resolved').length;
    const openPd = (pagerdutyIncidents || []).filter((p) => p.status !== 'resolved').length;
    return Math.max(openDb, openPd);
  }, [incidents, pagerdutyIncidents]);

  const activeAttackersCount = useMemo(() => {
    return overview?.total_attackers ?? (attackers || []).length;
  }, [overview, attackers]);

  const criticalThreatsCount = useMemo(() => {
    return (attackers || []).filter(
      (a) => a.risk_score >= 76 || a.risk_band === 'critical'
    ).length;
  }, [attackers]);

  const activeDecoySessionsCount = useMemo(() => {
    return (
      gatewayStats?.diverted_attackers_count ??
      gatewayStats?.diverted_sessions_count ??
      overview?.band_counts?.critical ??
      0
    );
  }, [gatewayStats, overview]);

  const gatewayRequestVolume = useMemo(() => {
    return (
      gatewayStats?.total_requests ??
      overview?.total_events ??
      metrics?.total_events ??
      0
    );
  }, [gatewayStats, overview, metrics]);

  // Sorted Incidents: Unresolved first, then highest risk/severity, then newest
  const sortedIncidents = useMemo(() => {
    return [...(incidents || [])].sort((a, b) => {
      if (a.status !== 'resolved' && b.status === 'resolved') return -1;
      if (a.status === 'resolved' && b.status !== 'resolved') return 1;
      const scoreA = a.risk_score_at_creation || (a.severity === 'critical' ? 90 : 50);
      const scoreB = b.risk_score_at_creation || (b.severity === 'critical' ? 90 : 50);
      if (scoreB !== scoreA) return scoreB - scoreA;
      return new Date(b.created_at || 0) - new Date(a.created_at || 0);
    });
  }, [incidents]);

  // Filtered Live Security Events
  const filteredEvents = useMemo(() => {
    if (!events || events.length === 0) return [];
    if (eventCategoryFilter === 'ALL') return events.slice(0, 10);
    return events
      .filter((ev) => {
        const cat = (ev.category || ev.event_type || '').toLowerCase();
        if (eventCategoryFilter === 'AUTH') return cat.includes('auth') || cat.includes('login') || cat.includes('otp');
        if (eventCategoryFilter === 'GATEWAY') return cat.includes('gateway') || cat.includes('probe') || cat.includes('recon');
        if (eventCategoryFilter === 'DECOY') return cat.includes('decoy') || cat.includes('divert') || cat.includes('honey');
        return true;
      })
      .slice(0, 10);
  }, [events, eventCategoryFilter]);

  // Attack activity over time chart data
  const chartData = metrics?.events_over_time || [];

  return (
    <div className="space-y-6 font-sans text-slate-200 pb-12">
      {/* Subtle non-blocking sync indicator */}
      {loading && !overview && (
        <div className="p-2 rounded bg-slate-900/60 border border-slate-800 flex items-center justify-between text-xs font-mono text-slate-400 animate-pulse">
          <div className="flex items-center space-x-2">
            <Loader2 className="h-3.5 w-3.5 text-cyan-400 animate-spin" />
            <span>Syncing telemetry with backend gateway ({BASE_URL})...</span>
          </div>
          <span className="text-[10px] text-slate-500">Live feeds active</span>
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* SECTION A: ENTERPRISE HEADER & CONTROLS                            */}
      {/* ------------------------------------------------------------------ */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div>
          <div className="flex items-center space-x-3">
            <h1 className="text-lg font-bold text-white tracking-wide font-mono flex items-center space-x-2">
              <ShieldCheck className="h-5 w-5 text-emerald-400" />
              <span>SENTINEL SECURITY OPERATIONS CENTRE</span>
            </h1>
            <span className="hidden sm:inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-emerald-950/60 border border-emerald-500/30 text-emerald-300">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 mr-1.5 animate-pulse"></span>
              ALL SYSTEMS OPERATIONAL
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-1 text-xs text-slate-400 font-mono">
            <span>Enterprise Deception Grid & Dynamic Risk Gateway</span>
            <span className="text-slate-600">&bull;</span>
            <span className="flex items-center space-x-1.5">
              <span
                className={`h-2 w-2 rounded-full ${
                  isLiveConnected ? 'bg-emerald-400' : 'bg-amber-400'
                }`}
              ></span>
              <span className={isLiveConnected ? 'text-slate-300' : 'text-amber-300'}>
                {isLiveConnected ? 'WebSocket Live Stream' : 'Connecting WebSocket...'}
              </span>
            </span>
            <span className="text-slate-600">&bull;</span>
            <span className="text-slate-400 flex items-center space-x-1">
              <Clock className="h-3 w-3 text-slate-500" />
              <span>{currentTime}</span>
            </span>
          </div>
        </div>

        {/* Operator Action Buttons */}
        <div className="flex items-center space-x-2.5">
          <button
            onClick={handleManualRefresh}
            disabled={refreshing}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700/80 text-slate-300 hover:text-white font-mono text-xs transition disabled:opacity-50"
            title="Refresh all SOC telemetry"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            <span>{refreshing ? 'Syncing...' : 'Refresh'}</span>
          </button>

          <button
            onClick={handleRunDemo}
            disabled={simLoading}
            className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 border border-slate-600 text-slate-100 font-mono text-xs font-semibold shadow-sm transition disabled:opacity-50"
          >
            {simLoading ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin text-cyan-400" />
            ) : (
              <Play className="h-3.5 w-3.5 fill-current text-cyan-400" />
            )}
            <span>{simLoading ? 'Injecting APT...' : 'Simulate Attack'}</span>
          </button>
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* SECTION B: EXECUTIVE SECURITY SUMMARY (5 Compact KPI Cards)        */}
      {/* ------------------------------------------------------------------ */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3.5">
        {/* KPI 1: Active Incidents */}
        <div
          onClick={() => navigate('/incidents')}
          className="p-3.5 rounded-lg bg-slate-900/90 border border-slate-800 hover:border-slate-700 cursor-pointer transition shadow-sm space-y-1"
        >
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>ACTIVE INCIDENTS</span>
            <AlertTriangle
              className={`h-4 w-4 ${
                activeIncidentsCount > 0 ? 'text-amber-400' : 'text-slate-500'
              }`}
            />
          </div>
          <div className="flex items-baseline justify-between pt-1">
            <span
              className={`text-2xl font-bold font-mono ${
                activeIncidentsCount > 0 ? 'text-amber-300' : 'text-white'
              }`}
            >
              {activeIncidentsCount}
            </span>
            <span className="text-[10px] font-mono text-slate-400">
              {activeIncidentsCount === 0 ? 'Clear' : 'Pending Action'}
            </span>
          </div>
        </div>

        {/* KPI 2: Active Attackers / Sessions */}
        <div
          onClick={() => navigate('/attackers')}
          className="p-3.5 rounded-lg bg-slate-900/90 border border-slate-800 hover:border-slate-700 cursor-pointer transition shadow-sm space-y-1"
        >
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>ATTACKER PROFILES</span>
            <Server className="h-4 w-4 text-slate-400" />
          </div>
          <div className="flex items-baseline justify-between pt-1">
            <span className="text-2xl font-bold font-mono text-white">
              {activeAttackersCount}
            </span>
            <span className="text-[10px] font-mono text-slate-400">Tracked IPs</span>
          </div>
        </div>

        {/* KPI 3: Critical Threats */}
        <div
          onClick={() => navigate('/attackers')}
          className="p-3.5 rounded-lg bg-slate-900/90 border border-slate-800 hover:border-red-500/40 cursor-pointer transition shadow-sm space-y-1"
        >
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>CRITICAL THREATS</span>
            <ShieldAlert className="h-4 w-4 text-red-400" />
          </div>
          <div className="flex items-baseline justify-between pt-1">
            <span className="text-2xl font-bold font-mono text-red-400">
              {criticalThreatsCount}
            </span>
            <span className="text-[10px] font-mono text-red-300 bg-red-950/60 px-1.5 py-0.5 rounded border border-red-500/30">
              Risk &ge; 76
            </span>
          </div>
        </div>

        {/* KPI 4: Active Decoy Sessions */}
        <div
          onClick={() => navigate('/gateway')}
          className="p-3.5 rounded-lg bg-slate-900/90 border border-slate-800 hover:border-slate-700 cursor-pointer transition shadow-sm space-y-1"
        >
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>DECOY SESSIONS</span>
            <GitBranch className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="flex items-baseline justify-between pt-1">
            <span className="text-2xl font-bold font-mono text-cyan-300">
              {activeDecoySessionsCount}
            </span>
            <span className="text-[10px] font-mono text-emerald-400">Isolated</span>
          </div>
        </div>

        {/* KPI 5: Gateway Request Volume */}
        <div
          onClick={() => navigate('/gateway')}
          className="p-3.5 rounded-lg bg-slate-900/90 border border-slate-800 hover:border-slate-700 cursor-pointer transition shadow-sm space-y-1 col-span-2 md:col-span-1"
        >
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>GATEWAY TRAFFIC</span>
            <Activity className="h-4 w-4 text-slate-400" />
          </div>
          <div className="flex items-baseline justify-between pt-1">
            <span className="text-2xl font-bold font-mono text-white">
              {gatewayRequestVolume}
            </span>
            <span className="text-[10px] font-mono text-slate-400">Total Ingested</span>
          </div>
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* SECTION C: INCIDENT OVERVIEW (Professional Table)                  */}
      {/* ------------------------------------------------------------------ */}
      <div className="rounded-lg bg-slate-900/90 border border-slate-800 overflow-hidden shadow-sm">
        <div className="p-3.5 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="h-4 w-4 text-amber-400" />
            <span className="font-mono text-xs font-bold text-white uppercase tracking-wider">
              Security Incidents Queue
            </span>
            <span className="text-[10px] font-mono text-slate-400 bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
              {sortedIncidents.length} Records
            </span>
          </div>

          <button
            onClick={() => navigate('/incidents')}
            className="text-xs font-mono text-slate-400 hover:text-white flex items-center space-x-1 transition"
          >
            <span>Full Incident Queue</span>
            <ChevronRight className="h-3.5 w-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs border-collapse">
            <thead>
              <tr className="bg-slate-950/60 border-b border-slate-800/80 text-[11px] text-slate-400 uppercase tracking-wider">
                <th className="py-2.5 px-3.5">Severity</th>
                <th className="py-2.5 px-3.5">Incident Title</th>
                <th className="py-2.5 px-3.5">Target / Session</th>
                <th className="py-2.5 px-3.5">Detection Source</th>
                <th className="py-2.5 px-3.5">Status</th>
                <th className="py-2.5 px-3.5">Detected At</th>
                <th className="py-2.5 px-3.5 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {sortedIncidents.length > 0 ? (
                sortedIncidents.slice(0, 5).map((inc) => {
                  const isCritical =
                    inc.severity === 'critical' || (inc.risk_score_at_creation && inc.risk_score_at_creation >= 76);
                  const isHigh = inc.severity === 'high' || (inc.risk_score_at_creation && inc.risk_score_at_creation >= 51);
                  const isResolved = inc.status === 'resolved';

                  return (
                    <tr
                      key={inc.id}
                      className="hover:bg-slate-800/40 transition group"
                    >
                      {/* Severity */}
                      <td className="py-2.5 px-3.5">
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                            isCritical
                              ? 'bg-red-950/80 text-red-300 border border-red-500/40'
                              : isHigh
                              ? 'bg-amber-950/80 text-amber-300 border border-amber-500/40'
                              : 'bg-slate-800 text-slate-300 border border-slate-700'
                          }`}
                        >
                          {inc.severity || (isCritical ? 'CRITICAL' : 'HIGH')}
                        </span>
                      </td>

                      {/* Title */}
                      <td className="py-2.5 px-3.5 max-w-xs font-medium text-slate-200">
                        <div className="truncate group-hover:text-white transition">
                          {inc.title}
                        </div>
                      </td>

                      {/* Associated Visitor / Session */}
                      <td className="py-2.5 px-3.5 text-slate-400">
                        {inc.attacker_id ? (
                          <button
                            onClick={() => setSelectedAttackerId(inc.attacker_id)}
                            className="text-cyan-400 hover:underline flex items-center space-x-1"
                          >
                            <span>IP #{inc.attacker_id}</span>
                          </button>
                        ) : (
                          <span className="text-slate-500">Gateway Session</span>
                        )}
                      </td>

                      {/* Detection Source */}
                      <td className="py-2.5 px-3.5 text-slate-400 text-[11px]">
                        Deception Gateway
                      </td>

                      {/* Status */}
                      <td className="py-2.5 px-3.5">
                        <span
                          className={`inline-block px-1.5 py-0.5 rounded text-[10px] uppercase font-semibold ${
                            isResolved
                              ? 'bg-emerald-950/40 text-emerald-300 border border-emerald-500/30'
                              : 'bg-amber-950/40 text-amber-300 border border-amber-500/30'
                          }`}
                        >
                          {inc.status}
                        </span>
                      </td>

                      {/* Timestamp */}
                      <td className="py-2.5 px-3.5 text-slate-400 text-[11px]">
                        {inc.created_at ? new Date(inc.created_at).toLocaleTimeString() : 'Recent'}
                      </td>

                      {/* Inspect Action */}
                      <td className="py-2.5 px-3.5 text-right">
                        <button
                          onClick={() => {
                            if (inc.attacker_id) setSelectedAttackerId(inc.attacker_id);
                            else navigate('/incidents');
                          }}
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-[11px] transition inline-flex items-center space-x-1"
                        >
                          <span>Inspect</span>
                          <ChevronRight className="h-3 w-3" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 font-mono text-xs">
                    No open security incidents recorded. Deception telemetry is nominal.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* SECTION D & E: LIVE ACTIVITY STREAM + THREAT INTELLIGENCE RADAR     */}
      {/* ------------------------------------------------------------------ */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* SECTION D: Compact Real-Time Event Stream (2 Columns) */}
        <div className="lg:col-span-2 rounded-lg bg-slate-900/90 border border-slate-800 p-4 space-y-3 shadow-sm">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-2.5">
            <div>
              <div className="font-mono text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-2">
                <Radio className="h-4 w-4 text-cyan-400" />
                <span>Live Security Telemetry Feed</span>
              </div>
              <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                Real-time honeypot, authentication, and gateway sensor telemetry
              </p>
            </div>

            {/* Event Category Filter Pills */}
            <div className="flex items-center space-x-1 font-mono text-[10px]">
              {['ALL', 'AUTH', 'GATEWAY', 'DECOY'].map((cat) => (
                <button
                  key={cat}
                  onClick={() => setEventCategoryFilter(cat)}
                  className={`px-2 py-0.5 rounded border transition ${
                    eventCategoryFilter === cat
                      ? 'bg-slate-800 border-slate-600 text-white font-bold'
                      : 'bg-slate-950/50 border-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {cat}
                </button>
              ))}
            </div>
          </div>

          {/* Event Stream List */}
          <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
            {filteredEvents.length > 0 ? (
              filteredEvents.map((ev, idx) => {
                const isCrit = ev.severity === 'critical' || (ev.risk_score && ev.risk_score >= 76);
                const isHigh = ev.severity === 'high' || (ev.risk_score && ev.risk_score >= 51);

                return (
                  <div
                    key={ev.id || idx}
                    className="p-2.5 rounded bg-slate-950/60 border border-slate-800/80 hover:border-slate-700 transition flex items-center justify-between gap-3 text-xs font-mono"
                  >
                    <div className="flex items-center space-x-2.5 min-w-0">
                      <span
                        className={`h-2 w-2 rounded-full shrink-0 ${
                          isCrit
                            ? 'bg-red-400'
                            : isHigh
                            ? 'bg-amber-400'
                            : 'bg-cyan-400'
                        }`}
                      ></span>
                      <div className="truncate">
                        <span className="font-semibold text-slate-200 mr-2">
                          {ev.event_type || ev.category || 'Security Event'}
                        </span>
                        <span className="text-slate-400 text-[11px]">
                          from IP {ev.src_ip || '127.0.0.1'}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center space-x-3 text-[11px] text-slate-400 shrink-0">
                      <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                        {ev.honeypot_type || 'gateway'}
                      </span>
                      <span>
                        {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : 'Now'}
                      </span>
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="text-center py-10 font-mono text-xs text-slate-500">
                Awaiting telemetry events from gateway and honeypot fleet...
              </div>
            )}
          </div>
        </div>

        {/* SECTION E: Threat Intelligence Card (1 Column) */}
        <div className="rounded-lg bg-slate-900/90 border border-slate-800 p-4 space-y-3.5 shadow-sm flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
              <div className="font-mono text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-2">
                <Layers className="h-4 w-4 text-slate-400" />
                <span>Threat Intelligence</span>
              </div>
              <button
                onClick={() => navigate('/universe')}
                className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
              >
                <span>Threat Radar</span>
                <ArrowUpRight className="h-3 w-3" />
              </button>
            </div>

            {/* Top Threat Adversaries List */}
            <div className="space-y-2">
              <div className="text-[11px] text-slate-400 font-mono uppercase tracking-wider">
                Top Priority Adversary Dossiers
              </div>
              {(attackers || []).length > 0 ? (
                (attackers || []).slice(0, 3).map((att) => (
                  <div
                    key={att.id}
                    onClick={() => setSelectedAttackerId(att.id)}
                    className="p-2.5 rounded bg-slate-950/60 border border-slate-800/80 hover:border-slate-700 cursor-pointer transition text-xs font-mono space-y-1"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-white font-semibold">{att.ip}</span>
                      <span
                        className={`text-[10px] font-bold ${
                          (att.risk_score || 0) >= 76
                            ? 'text-red-400'
                            : (att.risk_score || 0) >= 51
                            ? 'text-amber-400'
                            : 'text-emerald-400'
                        }`}
                      >
                        {att.risk_score ?? 0}/100 Risk
                      </span>
                    </div>
                    <div className="text-[10px] text-slate-400 flex items-center justify-between">
                      <span>Intent: {att.intent || 'Reconnaissance'}</span>
                      <span className="text-cyan-400 hover:underline">Inspect &rarr;</span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-[11px] text-slate-500 py-3 text-center">
                  Zero critical adversary profiles currently detected.
                </div>
              )}
            </div>
          </div>

          {/* Quick Toggle for Radar Preview */}
          <div className="pt-2 border-t border-slate-800/80">
            <button
              onClick={() => setShowUniverseRadar(!showUniverseRadar)}
              className="w-full py-2 rounded bg-slate-800/80 hover:bg-slate-800 border border-slate-700 text-xs font-mono text-slate-200 font-medium transition flex items-center justify-center space-x-1.5"
            >
              <Eye className="h-3.5 w-3.5 text-cyan-400" />
              <span>{showUniverseRadar ? 'Hide Orbital Radar' : 'Expand Orbital Radar View'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Expandable Threat Universe Radar (If activated by analyst) */}
      {showUniverseRadar && (
        <div className="rounded-lg bg-slate-900 border border-slate-800 p-4 space-y-2 animate-slide-in shadow-lg">
          <div className="flex items-center justify-between">
            <span className="font-mono text-xs font-bold text-white uppercase tracking-wider">
              Threat Universe Orbital Radar (Active Entity Gravity)
            </span>
            <button
              onClick={() => navigate('/universe')}
              className="text-xs font-mono text-cyan-400 hover:underline"
            >
              Open Fullscreen Workspace &rarr;
            </button>
          </div>
          <ThreatUniverse height={340} isPreview={true} onExpand={() => navigate('/universe')} />
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* SECTION F: REMEDIATION RECOMMENDATIONS (Compact Enterprise Card)   */}
      {/* ------------------------------------------------------------------ */}
      {advisorySummary && advisorySummary.top_recurring_fixes?.length > 0 && (
        <div className="rounded-lg bg-slate-900/90 border border-slate-800 p-4 space-y-3 shadow-sm font-mono text-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-2.5">
            <div className="flex items-center space-x-2">
              <Wrench className="h-4 w-4 text-slate-400" />
              <span className="font-bold text-white uppercase tracking-wider">
                Prioritized Remediation Recommendations
              </span>
              <span className="text-[10px] text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded border border-slate-700">
                AI suggestion, human review required
              </span>
            </div>

            <button
              onClick={() => navigate('/incidents')}
              className="text-[11px] text-slate-400 hover:text-white flex items-center space-x-1 transition"
            >
              <span>View All 11 Playbooks</span>
              <ChevronRight className="h-3.5 w-3.5" />
            </button>
          </div>

          {/* Compact Fix Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
            {(advisorySummary?.top_recurring_fixes || []).slice(0, 4).map((fix, idx) => (
              <div
                key={idx}
                className="p-3 rounded bg-slate-950/60 border border-slate-800 flex items-start space-x-3"
              >
                <CheckCircle2 className="h-4 w-4 text-emerald-400 mt-0.5 shrink-0" />
                <div className="space-y-1 min-w-0">
                  <div className="text-slate-100 font-semibold">{fix.step}</div>
                  <div className="text-[11px] text-slate-400 line-clamp-2">
                    {fix.why}
                  </div>
                  <div className="flex items-center space-x-3 pt-1 text-[10px] text-slate-500">
                    <span>Source: {fix.playbook_id || 'Playbook'}</span>
                    <span>&bull;</span>
                    <span className="text-amber-400">High Priority</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
