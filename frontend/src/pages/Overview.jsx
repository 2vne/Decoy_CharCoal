import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Users,
  ShieldAlert,
  Radio,
  Server,
  Play,
  Loader2,
  ArrowUpRight,
  AlertTriangle,
  Clock,
  ChevronRight,
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
import { Wrench, CheckCircle2, Sparkles } from 'lucide-react';
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
    metrics,
    runSimulation,
    setSelectedAttackerId,
    pagerdutyIncidents,
    pagerdutyStatus,
  } = useSoc();

  const [simLoading, setSimLoading] = useState(false);
  const [advisorySummary, setAdvisorySummary] = useState(null);

  useEffect(() => {
    api.getAdvisorySummary()
      .then((data) => setAdvisorySummary(data))
      .catch((err) => console.warn('Advisory summary load failed:', err.message));
  }, []);

  const handleRunDemo = async () => {
    setSimLoading(true);
    try {
      await runSimulation('full_chain', 2.0);
    } finally {
      setSimLoading(false);
    }
  };

  const criticalAttackers = attackers.filter((a) => a.risk_band === 'critical');
  const chartData = metrics?.events_over_time || [];

  if (loading && !overview && !backendError) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] space-y-4 font-mono">
        <Loader2 className="h-10 w-10 text-cyan-400 animate-spin" />
        <div className="text-sm text-cyan-300 font-bold tracking-wider animate-pulse">
          LOADING REAL-TIME SOC TELEMETRY...
        </div>
        <p className="text-xs text-soc-muted">
          Connecting to backend at {BASE_URL}
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Banner with Action Button */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold font-mono text-white tracking-wider flex items-center space-x-2">
            <span>TACTICAL SOC OVERVIEW</span>
            <span className="h-2 w-2 rounded-full bg-cyan-400 animate-ping"></span>
          </h1>
          <p className="text-xs text-soc-muted font-mono mt-0.5">
            Automated Deception Telemetry & Live Autonomous Response
          </p>
        </div>

        <button
          disabled={simLoading}
          onClick={handleRunDemo}
          className="flex items-center space-x-2 px-4 py-2 rounded bg-cyan-950 border border-cyan-400 text-cyan-200 font-mono text-xs font-bold hover:bg-cyan-900 shadow-[0_0_15px_rgba(0,240,255,0.25)] transition disabled:opacity-60"
        >
          {simLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4 fill-current" />}
          <span>{simLoading ? 'STARTING DEMO...' : 'RUN FULL APT DEMO'}</span>
        </button>
      </div>

      {/* PagerDuty On-Call Alerting Status Bar */}
      <div
        onClick={() => navigate('/incidents')}
        className="p-3 rounded border border-soc-border bg-soc-card hover:border-red-500/50 cursor-pointer transition flex flex-col sm:flex-row sm:items-center justify-between gap-3 font-mono text-xs shadow-sm"
      >
        <div className="flex items-center space-x-3">
          <div className="p-1.5 rounded bg-red-950/60 border border-red-500/40 text-red-400">
            <Radio className="h-4 w-4 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-white tracking-wide">PAGERDUTY ON-CALL:</span>
              <span className="text-emerald-400 font-bold uppercase">{pagerdutyStatus?.service_mode === 'operational' ? 'LIVE' : 'ACTIVE SIMULATED'}</span>
              <span className="text-soc-muted">&bull;</span>
              <span className="text-gray-300">Target: +91 {pagerdutyStatus?.responder_phone || '9372185727'}</span>
            </div>
            <div className="text-[10px] text-soc-muted mt-0.5">
              Email: {pagerdutyStatus?.responder_email || 'danishsjain@gmail.com'} &bull; Session Deduplication: Active
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          {pagerdutyIncidents?.filter((i) => i.priority === 'P1' && i.status !== 'resolved').length > 0 ? (
            <span className="px-2 py-1 rounded bg-red-950 border border-red-500 text-red-300 font-bold text-[10px] animate-pulse">
              🚨 {pagerdutyIncidents.filter((i) => i.priority === 'P1' && i.status !== 'resolved').length} P1 CRITICAL
            </span>
          ) : (
            <span className="px-2 py-1 rounded bg-emerald-950/80 border border-emerald-500/40 text-emerald-300 font-bold text-[10px]">
              ON-CALL HEALTHY
            </span>
          )}
          <span className="text-soc-muted text-[10px] flex items-center space-x-0.5">
            <span>Open PagerDuty</span>
            <ChevronRight className="h-3 w-3" />
          </span>
        </div>
      </div>

      {/* 4 KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Active Attackers */}
        <div
          onClick={() => navigate('/attackers')}
          className="p-4 rounded border border-soc-border bg-soc-card hover:border-cyan-500/50 cursor-pointer transition shadow-lg group"
        >
          <div className="flex items-center justify-between text-soc-muted">
            <span className="text-xs font-mono uppercase tracking-wider">Active Attackers</span>
            <Users className="h-4 w-4 text-cyan-400 group-hover:scale-110 transition" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-white">
              {overview?.total_attackers ?? attackers.length}
            </span>
            <span className="text-[10px] font-mono text-emerald-400 font-medium">Profiles Tracked</span>
          </div>
        </div>

        {/* Critical Threats */}
        <div
          onClick={() => {
            if (criticalAttackers.length > 0) {
              setSelectedAttackerId(criticalAttackers[0].id);
            } else {
              navigate('/attackers');
            }
          }}
          className="p-4 rounded border border-soc-border bg-soc-card hover:border-red-500/50 cursor-pointer transition shadow-lg group"
        >
          <div className="flex items-center justify-between text-soc-muted">
            <span className="text-xs font-mono uppercase tracking-wider">Critical Threats</span>
            <ShieldAlert className="h-4 w-4 text-red-400 group-hover:scale-110 transition" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-red-400">
              {overview?.band_counts?.critical ?? criticalAttackers.length}
            </span>
            <span className="text-[10px] font-mono text-red-300 font-medium bg-red-950/60 px-1.5 py-0.5 rounded border border-red-500/30">
              &ge; 76 Risk
            </span>
          </div>
        </div>

        {/* Events Today */}
        <div
          onClick={() => navigate('/events')}
          className="p-4 rounded border border-soc-border bg-soc-card hover:border-cyan-500/50 cursor-pointer transition shadow-lg group"
        >
          <div className="flex items-center justify-between text-soc-muted">
            <span className="text-xs font-mono uppercase tracking-wider">Events Today</span>
            <Radio className="h-4 w-4 text-cyber-blue group-hover:scale-110 transition" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-white">
              {overview?.events_today ?? 0}
            </span>
            <span className="text-[10px] font-mono text-soc-muted">Total: {overview?.total_events ?? 0}</span>
          </div>
        </div>

        {/* Honeypots Healthy */}
        <div
          onClick={() => navigate('/honeypots')}
          className="p-4 rounded border border-soc-border bg-soc-card hover:border-emerald-500/50 cursor-pointer transition shadow-lg group"
        >
          <div className="flex items-center justify-between text-soc-muted">
            <span className="text-xs font-mono uppercase tracking-wider">Honeypots Fleet</span>
            <Server className="h-4 w-4 text-emerald-400 group-hover:scale-110 transition" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-emerald-400">
              {overview?.honeypots_healthy ?? honeypots.filter((h) => h.status === 'running').length}/{honeypots.length || 4}
            </span>
            <span className="text-[10px] font-mono text-emerald-300 bg-emerald-950/60 px-1.5 py-0.5 rounded border border-emerald-500/30 font-medium">
              {overview?.honeypots_healthy && overview.honeypots_healthy === (honeypots.length || 4) ? '100% ONLINE' : 'OPERATIONAL'}
            </span>
          </div>
        </div>
      </div>

      {/* Remediation Advisor Overview Card */}
      {advisorySummary && advisorySummary.top_recurring_fixes?.length > 0 && (
        <div className="p-4 rounded-lg border border-purple-500/30 bg-purple-950/20 font-mono text-xs space-y-2.5 shadow-sm">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <div className="p-1 rounded bg-purple-900/60 border border-purple-500/50 text-purple-300">
                <Wrench className="h-4 w-4" />
              </div>
              <span className="font-bold text-white tracking-wide flex items-center gap-1.5">
                REMEDIATION ADVISOR &bull; TOP FIXES
                <span className="text-[10px] text-purple-300 bg-purple-950 px-1.5 py-0.5 rounded border border-purple-500/30">
                  AI suggestion, human review required
                </span>
              </span>
            </div>
            <button
              onClick={() => navigate('/incidents')}
              className="text-[11px] text-purple-300 hover:text-white flex items-center space-x-1"
            >
              <span>View All Incident Advisories</span>
              <ChevronRight className="h-3 w-3" />
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 pt-1">
            {advisorySummary.top_recurring_fixes.slice(0, 2).map((fix, idx) => (
              <div key={idx} className="p-2 rounded bg-slate-900/80 border border-slate-800 flex items-start space-x-2">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 mt-0.5 flex-shrink-0" />
                <div className="space-y-0.5 min-w-0">
                  <div className="text-white font-medium truncate">{fix.step}</div>
                  <div className="text-[10px] text-slate-400 truncate">{fix.why}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Threat Universe Preview Banner */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <h2 className="text-sm font-bold font-mono text-white uppercase tracking-wider">
              Threat Universe Orbital Radar
            </h2>
            <span className="text-[11px] font-mono text-soc-muted">
              (High risk entities gravitate towards the core sun)
            </span>
          </div>
          <button
            onClick={() => navigate('/universe')}
            className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
          >
            <span>FULLSCREEN VIEW</span>
            <ArrowUpRight className="h-3.5 w-3.5" />
          </button>
        </div>

        <ThreatUniverse
          height={380}
          isPreview={true}
          onExpand={() => navigate('/universe')}
        />
      </div>

      {/* Bottom Grid: Activity Chart & Recent Incidents */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* 2 Cols: Attack Activity Over Time */}
        <div className="lg:col-span-2 p-5 rounded border border-soc-border bg-soc-card space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-xs font-bold font-mono text-white uppercase tracking-wider">
                Deception Ingestion Telemetry
              </h3>
              <p className="text-[11px] font-mono text-soc-muted">Hourly honeypot event density</p>
            </div>
            <div className="flex items-center space-x-2 text-[10px] font-mono text-cyan-400">
              <span className="h-2 w-2 rounded-full bg-cyan-400"></span>
              <span>LIVE RATE</span>
            </div>
          </div>

          <div className="h-56 w-full">
            {chartData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData}>
                  <defs>
                    <linearGradient id="cyberArea" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00f0ff" stopOpacity={0.35} />
                      <stop offset="95%" stopColor="#00f0ff" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <XAxis
                    dataKey="hour"
                    stroke="#64748b"
                    fontSize={10}
                    tickLine={false}
                    fontFamily="JetBrains Mono"
                  />
                  <YAxis
                    stroke="#64748b"
                    fontSize={10}
                    tickLine={false}
                    fontFamily="JetBrains Mono"
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0b0f17',
                      border: '1px solid #1b253b',
                      borderRadius: '4px',
                      fontFamily: 'JetBrains Mono',
                      fontSize: '11px',
                    }}
                    itemStyle={{ color: '#00f0ff' }}
                  />
                  <Area
                    type="monotone"
                    dataKey="count"
                    stroke="#00f0ff"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#cyberArea)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-xs font-mono text-soc-muted space-y-1">
                <span>No hourly telemetry recorded yet</span>
                <span className="text-[10px]">Awaiting honeypot telemetry stream from backend</span>
              </div>
            )}
          </div>
        </div>

        {/* 1 Col: Recent Critical Incidents */}
        <div className="p-5 rounded border border-soc-border bg-soc-card flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold font-mono text-white uppercase tracking-wider">
                Active Incidents
              </h3>
              <span className="text-[10px] font-mono text-red-400 bg-red-950/60 px-2 py-0.5 rounded border border-red-500/30">
                {incidents.length} TICKETS
              </span>
            </div>

            <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
              {incidents.length > 0 ? (
                incidents.slice(0, 4).map((inc) => (
                  <div
                    key={inc.id}
                    onClick={() => {
                      if (inc.attacker_id) setSelectedAttackerId(inc.attacker_id);
                    }}
                    className="p-2.5 rounded bg-soc-surface border border-soc-border hover:border-red-500/50 cursor-pointer transition text-xs font-mono space-y-1"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-white truncate max-w-[180px]">
                        {inc.title}
                      </span>
                      <span className="text-[10px] uppercase font-bold text-red-400">
                        {inc.status}
                      </span>
                    </div>
                    <div className="text-[10px] text-soc-muted flex items-center justify-between">
                      <span>Created {new Date(inc.created_at).toLocaleTimeString()}</span>
                      <span className="text-cyan-400 flex items-center">
                        Investigate <ChevronRight className="h-3 w-3 ml-0.5" />
                      </span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-xs font-mono text-soc-muted text-center py-8">
                  No open incidents. All decoy surfaces calm.
                </div>
              )}
            </div>
          </div>

          <button
            onClick={() => navigate('/incidents')}
            className="w-full mt-4 py-2 rounded bg-soc-surface border border-soc-border hover:border-cyan-500/50 text-xs font-mono text-cyan-300 font-medium transition"
          >
            VIEW INCIDENT QUEUE &rarr;
          </button>
        </div>
      </div>
    </div>
  );
}
