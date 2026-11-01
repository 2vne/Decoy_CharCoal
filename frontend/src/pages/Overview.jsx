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
  Clock,
  ArrowUpRight,
  Activity,
} from 'lucide-react';
import { useSoc } from '../context/SocContext';
import { api } from '../api/client';

export default function Overview() {
  const navigate = useNavigate();
  const {
    loading,
    overview,
    attackers,
    incidents,
    events,
    metrics,
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

  // Live Metric Numbers (derived from real backend state)
  const activeIncidents = useMemo(() => {
    const openDb = (Array.isArray(incidents) ? incidents : []).filter(
      (i) => i?.status !== 'resolved'
    );
    const openPd = (Array.isArray(pagerdutyIncidents) ? pagerdutyIncidents : []).filter(
      (p) => p?.status !== 'resolved'
    );
    return openDb.length > 0 ? openDb : openPd;
  }, [incidents, pagerdutyIncidents]);

  const criticalThreatsCount = useMemo(() => {
    return (Array.isArray(attackers) ? attackers : []).filter(
      (a) => (a?.risk_score || 0) >= 76 || a?.risk_band === 'critical'
    ).length;
  }, [attackers]);

  const decoyDiversionCount = useMemo(() => {
    return (
      gatewayStats?.diverted_attackers_count ??
      gatewayStats?.diverted_sessions_count ??
      overview?.band_counts?.critical ??
      0
    );
  }, [gatewayStats, overview]);

  const totalGatewayRequests = useMemo(() => {
    return (
      gatewayStats?.total_requests ??
      overview?.total_events ??
      metrics?.total_events ??
      0
    );
  }, [gatewayStats, overview, metrics]);

  // Live Events Stream (Latest 10)
  const liveEvents = useMemo(() => {
    const list = Array.isArray(events) ? events : [];
    return list.slice(0, 10);
  }, [events]);

  return (
    <div className="space-y-5 font-sans text-slate-300 pb-10">
      {/* ------------------------------------------------------------------ */}
      {/* 1. TOP HEADER & CONTROLS                                           */}
      {/* ------------------------------------------------------------------ */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded bg-slate-800/80 border border-slate-700/80 text-slate-300">
            <ShieldCheck className="h-5 w-5 text-emerald-500" />
          </div>
          <div>
            <div className="flex items-center space-x-2.5">
              <h1 className="text-base font-semibold text-slate-100 tracking-wide font-mono">
                SENTINEL SOC
              </h1>
              <span
                className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-medium border ${
                  activeIncidents.length > 0
                    ? 'bg-amber-950/40 text-amber-300 border-amber-800/50'
                    : 'bg-emerald-950/40 text-emerald-400 border-emerald-800/50'
                }`}
              >
                <span
                  className={`h-1.5 w-1.5 rounded-full mr-1.5 ${
                    activeIncidents.length > 0 ? 'bg-amber-400' : 'bg-emerald-400'
                  }`}
                ></span>
                {activeIncidents.length > 0
                  ? `${activeIncidents.length} Active Incident${activeIncidents.length > 1 ? 's' : ''}`
                  : 'All Systems Operational'}
              </span>
            </div>
            <div className="flex items-center space-x-2 text-xs text-slate-500 font-mono mt-0.5">
              <span>{isLiveConnected ? 'Live Feed Connected' : 'Connecting to Stream...'}</span>
              <span>&bull;</span>
              <span>{currentTime}</span>
            </div>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center space-x-2">
          <button
            onClick={handleManualRefresh}
            disabled={refreshing}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-white font-mono text-xs transition disabled:opacity-50"
            title="Refresh latest telemetry"
          >
            <RefreshCw className={`h-3 w-3 ${refreshing ? 'animate-spin' : ''}`} />
            <span>{refreshing ? 'Syncing...' : 'Sync'}</span>
          </button>

          <button
            onClick={handleRunDemo}
            disabled={simLoading}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 hover:text-white font-mono text-xs font-medium transition disabled:opacity-50"
          >
            {simLoading ? (
              <Loader2 className="h-3 w-3 animate-spin text-slate-400" />
            ) : (
              <Play className="h-3 w-3 text-slate-400" />
            )}
            <span>{simLoading ? 'Simulating...' : 'Simulate Attack'}</span>
          </button>
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* 2. RESTRAINED KPI CARDS ROW                                        */}
      {/* ------------------------------------------------------------------ */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {/* KPI 1: Active Incidents */}
        <div
          onClick={() => navigate('/incidents')}
          className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-slate-700 cursor-pointer transition space-y-1"
        >
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>ACTIVE INCIDENTS</span>
            <AlertTriangle
              className={`h-3.5 w-3.5 ${
                activeIncidents.length > 0 ? 'text-amber-400' : 'text-slate-500'
              }`}
            />
          </div>
          <div className="flex items-baseline justify-between pt-1">
            <span
              className={`text-2xl font-bold font-mono ${
                activeIncidents.length > 0 ? 'text-amber-300' : 'text-slate-100'
              }`}
            >
              {activeIncidents.length}
            </span>
            <span className="text-[10px] font-mono text-slate-500">
              {activeIncidents.length > 0 ? 'Needs Review' : 'Nominal'}
            </span>
          </div>
        </div>

        {/* KPI 2: Critical Threats */}
        <div
          onClick={() => navigate('/attackers')}
          className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-slate-700 cursor-pointer transition space-y-1"
        >
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>CRITICAL THREATS</span>
            <ShieldAlert
              className={`h-3.5 w-3.5 ${
                criticalThreatsCount > 0 ? 'text-red-400' : 'text-slate-500'
              }`}
            />
          </div>
          <div className="flex items-baseline justify-between pt-1">
            <span
              className={`text-2xl font-bold font-mono ${
                criticalThreatsCount > 0 ? 'text-red-400' : 'text-slate-100'
              }`}
            >
              {criticalThreatsCount}
            </span>
            <span className="text-[10px] font-mono text-slate-500">Risk &ge; 76</span>
          </div>
        </div>

        {/* KPI 3: Decoy Diversions */}
        <div
          onClick={() => navigate('/gateway')}
          className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-slate-700 cursor-pointer transition space-y-1"
        >
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>DECOY SESSIONS</span>
            <GitBranch className="h-3.5 w-3.5 text-slate-400" />
          </div>
          <div className="flex items-baseline justify-between pt-1">
            <span className="text-2xl font-bold font-mono text-slate-100">
              {decoyDiversionCount}
            </span>
            <span className="text-[10px] font-mono text-emerald-500/80">Trapped</span>
          </div>
        </div>

        {/* KPI 4: Gateway Requests */}
        <div
          onClick={() => navigate('/gateway')}
          className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-slate-700 cursor-pointer transition space-y-1"
        >
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>GATEWAY TRAFFIC</span>
            <Activity className="h-3.5 w-3.5 text-slate-400" />
          </div>
          <div className="flex items-baseline justify-between pt-1">
            <span className="text-2xl font-bold font-mono text-slate-100">
              {totalGatewayRequests}
            </span>
            <span className="text-[10px] font-mono text-slate-500">Requests</span>
          </div>
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* 3. MAIN DYNAMIC PANELS: LIVE EVENTS & ACTIVE INCIDENTS             */}
      {/* ------------------------------------------------------------------ */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* LEFT PANEL: Real-time Live Security Events Feed */}
        <div className="rounded-lg bg-slate-900/60 border border-slate-800 p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
            <div className="flex items-center space-x-2">
              <Radio className="h-4 w-4 text-slate-400" />
              <span className="font-mono text-xs font-semibold text-slate-200 uppercase tracking-wider">
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
          <div className="space-y-1.5 max-h-[380px] overflow-y-auto pr-1">
            {liveEvents.length > 0 ? (
              liveEvents.map((ev, idx) => {
                const isCrit = ev?.severity === 'critical' || (ev?.risk_score && ev.risk_score >= 76);
                const isWarn = ev?.severity === 'high' || (ev?.risk_score && ev.risk_score >= 51);

                return (
                  <div
                    key={ev?.id || idx}
                    className="p-2.5 rounded bg-slate-950/50 border border-slate-800/60 flex items-center justify-between gap-3 text-xs font-mono hover:border-slate-700 transition"
                  >
                    <div className="flex items-center space-x-2.5 min-w-0">
                      <span
                        className={`h-2 w-2 rounded-full shrink-0 ${
                          isCrit ? 'bg-red-500' : isWarn ? 'bg-amber-400' : 'bg-slate-500'
                        }`}
                      ></span>
                      <div className="truncate">
                        <span className="text-slate-200 font-medium mr-2">
                          {ev?.event_type || ev?.category || 'Telemetry Event'}
                        </span>
                        <span className="text-slate-500 text-[11px]">
                          from {ev?.src_ip || '127.0.0.1'}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center space-x-2 shrink-0 text-[11px] text-slate-500">
                      <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400">
                        {ev?.honeypot || ev?.honeypot_type || 'gateway'}
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

        {/* RIGHT PANEL: Active Incidents Requiring Action */}
        <div className="rounded-lg bg-slate-900/60 border border-slate-800 p-4 space-y-3 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
              <div className="flex items-center space-x-2">
                <AlertTriangle className="h-4 w-4 text-slate-400" />
                <span className="font-mono text-xs font-semibold text-slate-200 uppercase tracking-wider">
                  Active Incidents Triage
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
            <div className="space-y-2 max-h-[380px] overflow-y-auto pr-1">
              {activeIncidents.length > 0 ? (
                activeIncidents.slice(0, 5).map((inc) => {
                  const isCritical =
                    inc.severity === 'critical' ||
                    inc.priority === 'P1' ||
                    (inc.risk_score_at_creation && inc.risk_score_at_creation >= 76);

                  return (
                    <div
                      key={inc.id || inc.dedup_key}
                      className="p-3 rounded bg-slate-950/50 border border-slate-800/80 hover:border-slate-700 transition flex items-start justify-between gap-3 text-xs font-mono"
                    >
                      <div className="space-y-1 min-w-0">
                        <div className="flex items-center space-x-2">
                          <span
                            className={`px-1.5 py-0.2 rounded text-[10px] font-bold uppercase ${
                              isCritical
                                ? 'bg-red-950/50 text-red-400 border border-red-900/60'
                                : 'bg-amber-950/50 text-amber-300 border border-amber-900/60'
                            }`}
                          >
                            {inc.priority || (isCritical ? 'CRITICAL' : 'HIGH')}
                          </span>
                          <span className="text-[10px] text-slate-500">
                            {inc.created_at ? new Date(inc.created_at).toLocaleTimeString() : 'Recent'}
                          </span>
                        </div>
                        <div className="text-slate-200 font-medium truncate">
                          {inc.title || inc.summary || 'Security Incident'}
                        </div>
                        {inc.attacker_id && (
                          <div className="text-[11px] text-slate-500">
                            Attacker ID #{inc.attacker_id}
                          </div>
                        )}
                      </div>

                      <button
                        onClick={() => {
                          if (inc.attacker_id) setSelectedAttackerId(inc.attacker_id);
                          else navigate('/incidents');
                        }}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-[11px] transition shrink-0"
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

          {/* Quick link to Threat Universe */}
          <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between text-xs font-mono">
            <span className="text-slate-500">Adversary Gravity Radar:</span>
            <button
              onClick={() => navigate('/universe')}
              className="text-slate-400 hover:text-white inline-flex items-center space-x-1 transition"
            >
              <span>Open Threat Universe</span>
              <ArrowUpRight className="h-3 w-3" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
