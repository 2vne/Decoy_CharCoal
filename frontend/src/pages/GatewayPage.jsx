import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Server,
  Activity,
  ArrowRight,
  TrendingUp,
  Play,
  RotateCcw,
  CheckCircle,
  Copy,
  ExternalLink,
  Lock,
  Layers,
  Zap,
} from 'lucide-react';
import { useSoc } from '../context/SocContext';
import { api } from '../api/client';

export default function GatewayPage() {
  const { addToast } = useSoc();
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [nginxConfig, setNginxConfig] = useState('');
  const [showConfig, setShowConfig] = useState(false);

  // Simulator state
  const [simIp, setSimIp] = useState('203.0.113.88');
  const [simPath, setSimPath] = useState('/auth/login');
  const [simMethod, setSimMethod] = useState('POST');
  const [simResult, setSimResult] = useState(null);
  const [simulating, setSimulating] = useState(false);

  const fetchGatewayData = async () => {
    try {
      setLoading(true);
      const [s, conf] = await Promise.all([
        api.getGatewayStats(),
        api.getNginxConfig().catch(() => ''),
      ]);
      setStats(s);
      setNginxConfig(conf);
    } catch (err) {
      console.error(err);
      addToast(`Gateway stats error: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGatewayData();
    const interval = setInterval(fetchGatewayData, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleSimulate = async () => {
    try {
      setSimulating(true);
      const res = await api.simulateGatewayTraffic({
        src_ip: simIp,
        path: simPath,
        method: simMethod,
      });
      setSimResult(res);
      addToast(`Traffic evaluated: Routed to ${res.routed_to.toUpperCase()}`, res.routed_to === 'decoy' ? 'warning' : 'info');
      fetchGatewayData();
    } catch (err) {
      addToast(`Evaluation error: ${err.message}`, 'error');
    } finally {
      setSimulating(false);
    }
  };

  const handleResetVisitor = async () => {
    try {
      const res = await api.resetVisitorDemo(simIp);
      addToast(res.message, 'success');
      setSimResult(null);
      fetchGatewayData();
    } catch (err) {
      addToast(`Reset error: ${err.message}`, 'error');
    }
  };

  const copyConfig = () => {
    navigator.clipboard.writeText(nginxConfig);
    addToast('NGINX configuration copied to clipboard', 'info');
  };

  return (
    <div className="space-y-6">
      {/* Title Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-lg p-5">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-blue-950/60 border border-blue-500/40 rounded-lg text-blue-400">
              <Server className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <h1 className="text-xl font-bold font-mono text-white tracking-wider flex items-center gap-2">
                DECEPTION GATEWAY & DYNAMIC TRAFFIC ROUTING
                <span className="text-xs px-2 py-0.5 rounded bg-emerald-950 border border-emerald-500/40 text-emerald-300">
                  REVERSE PROXY
                </span>
              </h1>
              <p className="text-xs font-mono text-slate-400 mt-1">
                NGINX auth_request subrequest architecture: Evaluates incoming visitor threat scores in real-time,
                dynamically routing legitimate users to the Real Application and adversaries to isolated Decoy Honeypots.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => setShowConfig(!showConfig)}
            className="flex items-center space-x-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-white rounded text-xs font-mono transition-all"
          >
            <Layers className="w-3.5 h-3.5" />
            <span>{showConfig ? 'Hide NGINX Config' : 'View NGINX Config'}</span>
          </button>
          <button
            onClick={fetchGatewayData}
            className="p-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 rounded text-xs font-mono transition-all"
            title="Refresh Gateway Telemetry"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* NGINX Config Viewer Modal / Accordion */}
      {showConfig && (
        <div className="bg-slate-950 border border-blue-500/40 rounded-lg p-5 font-mono text-xs space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <span className="text-blue-400 font-bold flex items-center gap-2">
              <Server className="w-4 h-4" />
              Production NGINX Configuration (sentinel_gateway.conf)
            </span>
            <button
              onClick={copyConfig}
              className="px-2 py-1 bg-blue-900/40 hover:bg-blue-800 text-blue-300 rounded border border-blue-500/30 flex items-center gap-1.5"
            >
              <Copy className="w-3.5 h-3.5" />
              Copy Configuration
            </button>
          </div>
          <pre className="bg-slate-900 p-4 rounded overflow-x-auto text-slate-300 leading-relaxed max-h-72">
            {nginxConfig || 'Loading configuration...'}
          </pre>
        </div>
      )}

      {/* Top Metrics Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-2">
            <span>TOTAL GATEWAY REQUESTS</span>
            <Activity className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">{stats?.total_requests || 0}</div>
          <div className="text-[11px] font-mono text-slate-500 mt-1">Proxied & evaluated requests</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-2">
            <span>REAL APP TRAFFIC</span>
            <CheckCircle className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">{stats?.real_traffic_count || 0}</div>
          <div className="text-[11px] font-mono text-slate-500 mt-1">Score: 0 - 30 (Trusted workload)</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-2">
            <span>DECOY TRAFFIC (DIVERTED)</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-red-400">{stats?.decoy_traffic_count || 0}</div>
          <div className="text-[11px] font-mono text-slate-500 mt-1">Score: 71 - 100 (Trapped in honeynet)</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-2">
            <span>DIVERTED ATTACKERS</span>
            <Lock className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400">{stats?.diverted_attackers_count || 0}</div>
          <div className="text-[11px] font-mono text-slate-500 mt-1">Distinct hostile IP addresses</div>
        </div>
      </div>

      {/* Two Column Layout: Interactive Simulator & Live Decisions Stream */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Interactive Gateway Traffic Simulator */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 font-mono space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Zap className="w-4 h-4 text-yellow-400" />
              Dynamic Routing Decision Simulator
            </h2>
            <span className="text-xs text-slate-400">Live Policy Test</span>
          </div>

          <p className="text-xs text-slate-400">
            Simulate a visitor reaching the reverse proxy. SENTINEL evaluates their real-time profile, function history, and temporal patterns to decide destination:
          </p>

          <div className="space-y-3 text-xs">
            <div>
              <label className="text-slate-300 block mb-1">Visitor / Attacker IP:</label>
              <input
                type="text"
                value={simIp}
                onChange={(e) => setSimIp(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-mono focus:border-blue-500 outline-none"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-slate-300 block mb-1">Target Path:</label>
                <input
                  type="text"
                  value={simPath}
                  onChange={(e) => setSimPath(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-mono focus:border-blue-500 outline-none"
                />
              </div>
              <div>
                <label className="text-slate-300 block mb-1">HTTP Method:</label>
                <select
                  value={simMethod}
                  onChange={(e) => setSimMethod(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-mono focus:border-blue-500 outline-none"
                >
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                  <option value="DELETE">DELETE</option>
                </select>
              </div>
            </div>

            <div className="flex gap-2">
              <button
                onClick={handleSimulate}
                disabled={simulating}
                className="flex-1 py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded transition-all flex items-center justify-center space-x-2 disabled:opacity-50"
              >
                <Play className="w-4 h-4 fill-current" />
                <span>{simulating ? 'Evaluating...' : 'Dispatch Request & Evaluate Route'}</span>
              </button>
              <button
                onClick={handleResetVisitor}
                title="Reset this IP's risk score and function history for controlled re-demonstration"
                className="px-3 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white font-bold rounded transition-all flex items-center justify-center space-x-1 border border-slate-700"
              >
                <RotateCcw className="w-4 h-4" />
                <span>Reset Demo IP</span>
              </button>
            </div>
          </div>

          {/* Simulator Result Box */}
          {simResult && (
            <div className="mt-4 p-4 rounded bg-slate-950 border border-slate-800 space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Decision Route:</span>
                <span
                  className={`px-2 py-0.5 rounded font-bold uppercase ${
                    simResult.routed_to === 'decoy'
                      ? 'bg-red-950 text-red-400 border border-red-500/50'
                      : simResult.routed_to === 'challenge'
                      ? 'bg-yellow-950 text-yellow-400 border border-yellow-500/50'
                      : 'bg-emerald-950 text-emerald-400 border border-emerald-500/50'
                  }`}
                >
                  {simResult.routed_to} (Risk: {simResult.risk_score.toFixed(1)}/100)
                </span>
              </div>
              <div className="text-slate-400">
                Dispatched Destination: <span className="text-blue-300 font-bold">{simResult.dispatched_url}</span>
              </div>
              <div className="text-slate-400 bg-slate-900/60 p-2 rounded border border-slate-850 italic">
                &ldquo;{simResult.decision_reason}&rdquo;
              </div>
            </div>
          )}

          {/* Policy Legend */}
          <div className="mt-4 pt-3 border-t border-slate-800/80 text-[11px] text-slate-500 space-y-1">
            <div>• <span className="text-emerald-400 font-bold">0 – 30 pts:</span> Routed directly to Real Application workload.</div>
            <div>• <span className="text-yellow-400 font-bold">31 – 70 pts:</span> Subjected to rate-limiting or verification challenge.</div>
            <div>• <span className="text-red-400 font-bold">71 – 100 pts:</span> Seamlessly diverted to isolated Decoy Honeypot.</div>
          </div>
        </div>

        {/* Right: Recent Gateway Decisions Stream */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 flex flex-col font-mono">
          <div className="flex items-center justify-between mb-4 border-b border-slate-800 pb-3">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Activity className="w-4 h-4 text-emerald-400" />
              Recent Gateway Routing Decisions
            </h2>
            <span className="text-xs text-slate-400">Telemetry Feed</span>
          </div>

          <div className="space-y-2.5 flex-1 overflow-y-auto max-h-[500px]">
            {(!stats?.recent_decisions || stats.recent_decisions.length === 0) ? (
              <div className="text-center py-12 text-xs text-slate-500">
                No gateway requests recorded yet. Use the simulator to test live routing decisions.
              </div>
            ) : (
              stats.recent_decisions.map((log) => (
                <div
                  key={log.id}
                  className="bg-slate-950/70 border border-slate-800/80 rounded p-3 text-xs hover:border-slate-700 transition-all"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <span className="font-bold text-slate-200">{log.src_ip}</span>
                      <span className="text-slate-500">{log.method} {log.path}</span>
                    </div>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                        log.routed_to === 'decoy'
                          ? 'bg-red-950 text-red-400 border border-red-500/40'
                          : log.routed_to === 'challenge'
                          ? 'bg-yellow-950 text-yellow-400 border border-yellow-500/40'
                          : 'bg-emerald-950 text-emerald-400 border border-emerald-500/40'
                      }`}
                    >
                      {log.routed_to} ({log.risk_score?.toFixed(0) || 0})
                    </span>
                  </div>

                  <div className="mt-1.5 text-[11px] text-slate-400 bg-slate-900/60 p-2 rounded border border-slate-800/60">
                    {log.decision_reason}
                  </div>

                  <div className="mt-2 pt-1.5 border-t border-slate-800/60 flex items-center justify-between text-[10px] text-slate-500">
                    <span>Latency: {log.response_time_ms}ms</span>
                    <span>{log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : 'now'}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

