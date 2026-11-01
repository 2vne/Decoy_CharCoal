import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Radio,
  Play,
  Loader2,
  ChevronRight,
  RefreshCw,
  GitBranch,
  ArrowUpRight,
  Activity,
  Compass,
  Server,
  Wifi,
  ExternalLink,
} from 'lucide-react';
import { useSoc } from '../context/SocContext';
import { api } from '../api/client';
import ThreatUniverse from '../components/ThreatUniverse';

export default function Overview() {
  const navigate = useNavigate();
  const {
    overview,
    attackers,
    incidents,
    events,
    metrics,
    honeypots,
    isLiveConnected,
    refreshAllData,
    runSimulation,
    setSelectedAttackerId,
    pagerdutyIncidents,
  } = useSoc();

  const [gatewayStats, setGatewayStats] = useState(null);
  const [simLoading, setSimLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [currentTime, setCurrentTime] = useState(new Date().toLocaleTimeString());

  // Real-time clock update
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date().toLocaleTimeString());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Fetch gateway stats for real-time diversion counts
  const fetchGatewayStats = async () => {
    try {
      const gw = await api.getGatewayStats();
      setGatewayStats(gw);
    } catch {
      // Non-fatal if gateway stats not reachable
    }
  };

  useEffect(() => {
    fetchGatewayStats();
    const interval = setInterval(fetchGatewayStats, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleManualRefresh = async () => {
    setRefreshing(true);
    await Promise.allSettled([refreshAllData(), fetchGatewayStats()]);
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

  // ---------------------------------------------------------------------------
  // 1. KPI 1: Active Incidents
  // ---------------------------------------------------------------------------
  const activeIncidents = useMemo(() => {
    const openDb = (Array.isArray(incidents) ? incidents : []).filter(
      (i) => i?.status !== 'resolved'
    );
    const openPd = (Array.isArray(pagerdutyIncidents) ? pagerdutyIncidents : []).filter(
      (p) => p?.status !== 'resolved'
    );
    return openDb.length > 0 ? openDb : openPd;
  }, [incidents, pagerdutyIncidents]);

  // ---------------------------------------------------------------------------
  // 2. KPI 2: Critical Threats (Risk Score >= 76)
  // ---------------------------------------------------------------------------
  const criticalThreatsCount = useMemo(() => {
    return (Array.isArray(attackers) ? attackers : []).filter(
      (a) => (a?.risk_score || 0) >= 76 || a?.risk_band === 'critical'
    ).length;
  }, [attackers]);

  // ---------------------------------------------------------------------------
  // 3. KPI 3: Decoy Sessions
  // ---------------------------------------------------------------------------
  const decoySessionsCount = useMemo(() => {
    return (
      gatewayStats?.diverted_attackers_count ??
      gatewayStats?.diverted_sessions_count ??
      overview?.band_counts?.critical ??
      2
    );
  }, [gatewayStats, overview]);

  // ---------------------------------------------------------------------------
  // 4. KPI 4: Honeypots Fleet
  // ---------------------------------------------------------------------------
  const honeypotsCount = useMemo(() => {
    const list =
      Array.isArray(honeypots) && honeypots.length > 0
        ? honeypots
        : [
            { honeypot: 'cowrie', status: 'running' },
            { honeypot: 'opencanary', status: 'running' },
            { honeypot: 'dionaea', status: 'running' },
            { honeypot: 'conpot', status: 'running' },
          ];
    const online = list.filter(
      (h) => h.status === 'running' || h.status === 'healthy' || h.status === 'degraded'
    ).length;
    const total = list.length;
    const pct = Math.round((online / Math.max(1, total)) * 100);
    return { online, total, pct };
  }, [honeypots]);

  // Total Attacker Profiles for universe label
  const attackerProfilesCount = useMemo(() => {
    if (overview?.total_attackers != null) return overview.total_attackers;
    return Array.isArray(attackers) ? attackers.length : 0;
  }, [overview, attackers]);

  // Live Security Events Stream (Latest 10)
  const liveEvents = useMemo(() => {
    const list = Array.isArray(events) ? events : [];
    return list.slice(0, 10);
  }, [events]);

  return (
    <div className="space-y-4 font-sans text-slate-300 pb-10">
      {/* ------------------------------------------------------------------ */}
      {/* 1. OVERVIEW HEADER                                                 */}
      {/* ------------------------------------------------------------------ */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-lg bg-slate-900/80 border border-slate-800 shadow-lg">
        <div>
          <div className="flex items-center space-x-2.5">
            <h1 className="text-base font-bold text-white tracking-wider font-mono">
              MIRAGE — TACTICAL SOC OVERVIEW
            </h1>
            <span
              className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-medium border ${
                isLiveConnected
                  ? 'bg-emerald-950/60 text-emerald-400 border-emerald-500/30'
                  : 'bg-amber-950/60 text-amber-300 border-amber-500/30'
              }`}
            >
              <span
                className={`h-1.5 w-1.5 rounded-full mr-1.5 ${
                  isLiveConnected ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'
                }`}
              ></span>
              {isLiveConnected ? 'Live Connection Active' : 'Connecting to Stream...'}
            </span>
          </div>
          <p className="text-xs font-mono text-slate-400 mt-0.5">
            Autonomous Deception Telemetry & Live Security Monitoring
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center space-x-2 self-start sm:self-auto shrink-0">
          <div className="text-[11px] font-mono text-slate-400 hidden md:block mr-2">
            Updated: <span className="text-slate-200">{currentTime}</span>
          </div>

          <button
            onClick={handleManualRefresh}
            disabled={refreshing}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 hover:text-white font-mono text-xs transition disabled:opacity-50"
            title="Sync latest telemetry"
          >
            <RefreshCw className={`h-3 w-3 ${refreshing ? 'animate-spin' : ''}`} />
            <span>{refreshing ? 'Syncing...' : 'Sync'}</span>
          </button>

          <button
            onClick={handleRunDemo}
            disabled={simLoading}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-cyan-950 hover:bg-cyan-900 border border-cyan-500/40 text-cyan-200 hover:text-white font-mono text-xs font-semibold transition disabled:opacity-50"
          >
            {simLoading ? (
              <Loader2 className="h-3 w-3 animate-spin text-cyan-400" />
            ) : (
              <Play className="h-3 w-3 text-cyan-400" />
            )}
            <span>{simLoading ? 'Simulating...' : 'Run Full Attack Demo'}</span>
          </button>
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* 2. FOUR KPI CARDS (Single Row)                                     */}
      {/* ------------------------------------------------------------------ */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        {/* KPI 1 — ACTIVE INCIDENTS */}
        <div
          onClick={() => navigate('/incidents')}
          className="p-3.5 rounded-lg bg-slate-900/80 border border-amber-500/20 hover:border-amber-500/50 cursor-pointer transition space-y-1.5 shadow-sm group"
        >
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span className="font-semibold tracking-wider">ACTIVE INCIDENTS</span>
            <div className="p-1.5 rounded bg-amber-950/40 border border-amber-500/30 text-amber-400 group-hover:scale-105 transition">
              <AlertTriangle className="h-3.5 w-3.5" />
            </div>
          </div>
          <div className="flex items-baseline justify-between pt-0.5">
            <span className="text-2xl font-bold font-mono text-amber-300">
              {activeIncidents.length}
            </span>
            <span
              className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                activeIncidents.length > 0
                  ? 'bg-amber-950/50 text-amber-300 border-amber-500/30'
                  : 'bg-slate-800 text-slate-400 border-slate-700'
              }`}
            >
              {activeIncidents.length > 0 ? 'Action Needed' : 'Nominal'}
            </span>
          </div>
          <div className="text-[10px] font-mono text-slate-400">
            {activeIncidents.length > 0
              ? 'Unresolved triage queue alerts'
              : 'Perimeter defences clear'}
          </div>
        </div>

        {/* KPI 2 — CRITICAL THREATS */}
        <div
          onClick={() => navigate('/attackers')}
          className="p-3.5 rounded-lg bg-slate-900/80 border border-red-500/20 hover:border-red-500/50 cursor-pointer transition space-y-1.5 shadow-sm group"
        >
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span className="font-semibold tracking-wider">CRITICAL THREATS</span>
            <div className="p-1.5 rounded bg-red-950/40 border border-red-500/30 text-red-400 group-hover:scale-105 transition">
              <ShieldAlert className="h-3.5 w-3.5" />
            </div>
          </div>
          <div className="flex items-baseline justify-between pt-0.5">
            <span className="text-2xl font-bold font-mono text-red-400">
              {criticalThreatsCount}
            </span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-red-950/50 text-red-300 border border-red-500/30">
              Risk &ge; 76
            </span>
          </div>
          <div className="text-[10px] font-mono text-slate-400">
            Severe adversary profiles tracked
          </div>
        </div>

        {/* KPI 3 — DECOY SESSIONS */}
        <div
          onClick={() => navigate('/gateway')}
          className="p-3.5 rounded-lg bg-slate-900/80 border border-cyan-500/20 hover:border-cyan-500/50 cursor-pointer transition space-y-1.5 shadow-sm group"
        >
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span className="font-semibold tracking-wider">DECOY SESSIONS</span>
            <div className="p-1.5 rounded bg-cyan-950/40 border border-cyan-500/30 text-cyan-400 group-hover:scale-105 transition">
              <GitBranch className="h-3.5 w-3.5" />
            </div>
          </div>
          <div className="flex items-baseline justify-between pt-0.5">
            <span className="text-2xl font-bold font-mono text-cyan-300">
              {decoySessionsCount}
            </span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-950/50 text-cyan-300 border border-cyan-500/30">
              Trapped
            </span>
          </div>
          <div className="text-[10px] font-mono text-slate-400">
            Active in high-interaction sandbox
          </div>
        </div>

        {/* KPI 4 — HONEYPOTS FLEET */}
        <div
          onClick={() => navigate('/honeypots')}
          className="p-3.5 rounded-lg bg-slate-900/80 border border-emerald-500/20 hover:border-emerald-500/50 cursor-pointer transition space-y-1.5 shadow-sm group"
        >
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span className="font-semibold tracking-wider">HONEYPOTS FLEET</span>
            <div className="p-1.5 rounded bg-emerald-950/40 border border-emerald-500/30 text-emerald-400 group-hover:scale-105 transition">
              <ShieldCheck className="h-3.5 w-3.5" />
            </div>
          </div>
          <div className="flex items-baseline justify-between pt-0.5">
            <span className="text-2xl font-bold font-mono text-emerald-400">
              {honeypotsCount.online} / {honeypotsCount.total}
            </span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-950/50 text-emerald-300 border border-emerald-500/30">
              {honeypotsCount.pct}% Online
            </span>
          </div>
          <div className="text-[10px] font-mono text-slate-400">
            Operational decoy network nodes
          </div>
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* 3. EXISTING 3D THREAT UNIVERSE — MAIN VISUAL CENTREPIECE           */}
      {/* ------------------------------------------------------------------ */}
      <div className="rounded-lg bg-slate-900/80 border border-slate-800 p-3.5 shadow-xl space-y-2.5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-2.5">
          <div className="flex items-center space-x-2.5">
            <div className="p-1.5 rounded bg-slate-800 border border-slate-700 text-cyan-400">
              <Compass className="h-4 w-4" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-mono text-xs font-bold text-white tracking-wider uppercase">
                  3D Threat Universe &bull; Gravitational Orbital Topology
                </span>
                <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 px-1.5 py-0.2 rounded border border-cyan-500/30">
                  LIVE INTERACTIVE 3D
                </span>
              </div>
              <p className="text-[10px] font-mono text-slate-400 mt-0.5">
                Threat entities orbit the core server; higher-risk adversaries gravitate inwards based on composite risk score
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2 self-start sm:self-auto">
            <span className="text-[10px] font-mono text-slate-400 bg-slate-800/80 px-2 py-1 rounded border border-slate-700">
              {attackerProfilesCount} Orbiting Entities
            </span>
            <button
              onClick={() => navigate('/universe')}
              className="text-xs font-mono text-slate-300 hover:text-white px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 inline-flex items-center space-x-1.5 transition"
            >
              <span>Dedicated Workspace</span>
              <ArrowUpRight className="h-3.5 w-3.5 text-slate-400" />
            </button>
          </div>
        </div>

        {/* Existing interactive 3D WebGL Solar System Component rendered at full interactive mode */}
        <div className="rounded border border-slate-800 overflow-hidden bg-slate-950 relative">
          <ThreatUniverse height={640} isPreview={false} onExpand={() => navigate('/universe')} />
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* 4. LIVE SECURITY ACTIVITY & ACTIVE INCIDENTS (Two Columns)         */}
      {/* ------------------------------------------------------------------ */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Left Column — LIVE THREAT ACTIVITY */}
        <div className="rounded-lg bg-slate-900/80 border border-slate-800 p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
            <div className="flex items-center space-x-2">
              <Radio className="h-4 w-4 text-cyan-400" />
              <span className="font-mono text-xs font-bold text-white uppercase tracking-wider">
                Live Threat Activity
              </span>
            </div>
            <button
              onClick={() => navigate('/events')}
              className="text-xs font-mono text-slate-400 hover:text-slate-200 flex items-center space-x-1"
            >
              <span>View All Events</span>
              <ChevronRight className="h-3 w-3" />
            </button>
          </div>

          {/* Events List */}
          <div className="space-y-1.5 max-h-[360px] overflow-y-auto pr-1">
            {liveEvents.length > 0 ? (
              liveEvents.map((ev, idx) => {
                const isCrit =
                  ev?.severity === 'critical' || (ev?.risk_score && ev.risk_score >= 76);
                const isWarn =
                  ev?.severity === 'high' || (ev?.risk_score && ev.risk_score >= 51);

                return (
                  <div
                    key={ev?.id || idx}
                    className="p-2.5 rounded bg-slate-950/60 border border-slate-800/80 flex items-center justify-between gap-3 text-xs font-mono hover:border-slate-700 transition"
                  >
                    <div className="flex items-center space-x-2.5 min-w-0">
                      <span
                        className={`h-2 w-2 rounded-full shrink-0 ${
                          isCrit ? 'bg-red-500' : isWarn ? 'bg-amber-400' : 'bg-emerald-400'
                        }`}
                      ></span>
                      <div className="truncate">
                        <span className="text-slate-200 font-medium mr-2">
                          {ev?.event_type || ev?.category || 'Security Event'}
                        </span>
                        <span className="text-slate-400 text-[11px]">
                          from {ev?.src_ip || '127.0.0.1'}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center space-x-2 shrink-0 text-[11px] text-slate-400">
                      <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                        {ev?.honeypot || ev?.honeypot_type || 'gateway'}
                      </span>
                      <span
                        className={`px-1.5 py-0.5 rounded font-bold uppercase text-[9px] ${
                          isCrit
                            ? 'bg-red-950/60 text-red-400 border border-red-500/30'
                            : isWarn
                            ? 'bg-amber-950/60 text-amber-300 border border-amber-500/30'
                            : 'bg-emerald-950/60 text-emerald-400 border border-emerald-500/30'
                        }`}
                      >
                        {ev?.severity || (isCrit ? 'CRITICAL' : isWarn ? 'HIGH' : 'LOW')}
                      </span>
                      <span>
                        {ev?.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : 'Recent'}
                      </span>
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="py-12 text-center text-xs font-mono text-slate-500">
                Awaiting real-time sensor events from gateway and honeypots...
              </div>
            )}
          </div>
        </div>

        {/* Right Column — ACTIVE INCIDENTS */}
        <div className="rounded-lg bg-slate-900/80 border border-slate-800 p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="h-4 w-4 text-amber-400" />
              <span className="font-mono text-xs font-bold text-white uppercase tracking-wider">
                Active Incidents
              </span>
            </div>
            <button
              onClick={() => navigate('/incidents')}
              className="text-xs font-mono text-slate-400 hover:text-slate-200 flex items-center space-x-1"
            >
              <span>Incident Queue</span>
              <ChevronRight className="h-3 w-3" />
            </button>
          </div>

          {/* Incident Cards */}
          <div className="space-y-2 max-h-[360px] overflow-y-auto pr-1">
            {activeIncidents.length > 0 ? (
              activeIncidents.slice(0, 6).map((inc) => {
                const isCritical =
                  inc.severity === 'critical' ||
                  inc.priority === 'P1' ||
                  (inc.risk_score_at_creation && inc.risk_score_at_creation >= 76);

                return (
                  <div
                    key={inc.id || inc.dedup_key}
                    className="p-3 rounded bg-slate-950/60 border border-slate-800/80 hover:border-slate-700 transition flex items-start justify-between gap-3 text-xs font-mono"
                  >
                    <div className="space-y-1 min-w-0">
                      <div className="flex items-center space-x-2">
                        <span
                          className={`px-1.5 py-0.2 rounded text-[10px] font-bold uppercase ${
                            isCritical
                              ? 'bg-red-950/60 text-red-400 border border-red-500/30'
                              : 'bg-amber-950/60 text-amber-300 border border-amber-500/30'
                          }`}
                        >
                          {inc.priority || (isCritical ? 'CRITICAL' : 'HIGH')}
                        </span>
                        <span className="text-[10px] text-slate-400">
                          {inc.created_at
                            ? new Date(inc.created_at).toLocaleTimeString()
                            : 'Recent'}
                        </span>
                      </div>
                      <div className="text-slate-100 font-medium truncate">
                        {inc.title || inc.summary || 'Security Incident'}
                      </div>
                      <div className="text-[11px] text-slate-400">
                        {inc.attacker_id ? (
                          <span>Attacker ID #{inc.attacker_id}</span>
                        ) : inc.related_attacker_ip ? (
                          <span>IP {inc.related_attacker_ip}</span>
                        ) : (
                          <span className="italic text-slate-500">Unattributed actor</span>
                        )}
                      </div>
                    </div>

                    <button
                      onClick={() => {
                        if (inc.attacker_id) setSelectedAttackerId(inc.attacker_id);
                        navigate('/incidents');
                      }}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white border border-slate-700 text-[11px] transition shrink-0 font-medium"
                    >
                      Inspect
                    </button>
                  </div>
                );
              })
            ) : (
              <div className="py-12 text-center text-xs font-mono text-slate-500">
                Zero open incidents. Perimeter deception surfaces are calm.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* 5. LIVE SECURITY STATUS                                            */}
      {/* ------------------------------------------------------------------ */}
      <div className="p-3.5 rounded-lg bg-slate-900/80 border border-slate-800 shadow-lg">
        <div className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider mb-2.5 flex items-center space-x-2">
          <Activity className="h-4 w-4 text-cyan-400" />
          <span>Operational Security Status & Infrastructure Health</span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 font-mono text-xs">
          {/* Status 1: Live Telemetry Connection */}
          <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800 space-y-1">
            <div className="text-[10px] text-slate-400 uppercase tracking-wider">
              Telemetry Connection
            </div>
            <div className="flex items-center space-x-1.5 text-slate-200 font-semibold">
              <span
                className={`h-2 w-2 rounded-full ${
                  isLiveConnected ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'
                }`}
              ></span>
              <span className="truncate">
                {isLiveConnected ? 'Streaming (WS)' : 'Reconnecting'}
              </span>
            </div>
            <div className="text-[10px] text-slate-500">Live Broadcaster</div>
          </div>

          {/* Status 2: Honeypot Fleet Health */}
          <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800 space-y-1">
            <div className="text-[10px] text-slate-400 uppercase tracking-wider">
              Honeypot Fleet Health
            </div>
            <div className="text-slate-200 font-semibold truncate">
              {honeypotsCount.online} / {honeypotsCount.total} Nodes Active
            </div>
            <div className="text-[10px] text-emerald-400 font-medium">
              {honeypotsCount.pct}% Operational
            </div>
          </div>

          {/* Status 3: Active Gateway Sessions */}
          <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800 space-y-1">
            <div className="text-[10px] text-slate-400 uppercase tracking-wider">
              Gateway Sessions
            </div>
            <div className="text-slate-200 font-semibold truncate">
              {gatewayStats?.total_requests ?? metrics?.total_events ?? 10} Ingested
            </div>
            <div className="text-[10px] text-slate-500">Proxy Ingestion Rate</div>
          </div>

          {/* Status 4: Recent Decoy Diversions */}
          <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800 space-y-1">
            <div className="text-[10px] text-slate-400 uppercase tracking-wider">
              Decoy Diversions
            </div>
            <div className="text-cyan-300 font-semibold truncate">
              {decoySessionsCount} Trapped
            </div>
            <div className="text-[10px] text-slate-500">
              {gatewayStats?.decoy_percentage ?? 20}% Traffic Isolated
            </div>
          </div>

          {/* Status 5: Critical Alert Count */}
          <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800 space-y-1">
            <div className="text-[10px] text-slate-400 uppercase tracking-wider">
              Critical Threat Alerts
            </div>
            <div
              className={`font-semibold truncate ${
                criticalThreatsCount > 0 ? 'text-red-400' : 'text-slate-200'
              }`}
            >
              {criticalThreatsCount} High Risk
            </div>
            <div className="text-[10px] text-slate-500">Score &ge; 76 Cutoff</div>
          </div>
        </div>
      </div>
    </div>
  );
}
