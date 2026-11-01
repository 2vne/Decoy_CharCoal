import React, { useState, useEffect, useMemo } from 'react';
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
  UserCheck,
  ChevronRight,
  Info,
  X,
  AlertTriangle,
  Search,
  Filter,
  Eye,
  Sliders,
  ShieldCheck,
  History,
} from 'lucide-react';
import { useSoc } from '../context/SocContext';
import { api } from '../api/client';

export default function GatewayPage() {
  const { addToast } = useSoc();
  const [stats, setStats] = useState(null);
  const [sessions, setSessions] = useState([]);
  const [pointAllocations, setPointAllocations] = useState({});
  const [selectedSession, setSelectedSession] = useState(null);
  const [sessionDetail, setSessionDetail] = useState(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [loading, setLoading] = useState(true);
  const [nginxConfig, setNginxConfig] = useState('');
  const [showConfig, setShowConfig] = useState(false);
  const [showAllocations, setShowAllocations] = useState(false);

  // Filters for sessions table
  const [searchQuery, setSearchQuery] = useState('');
  const [classificationFilter, setClassificationFilter] = useState('ALL');
  const [routeFilter, setRouteFilter] = useState('ALL');

  // Simulator state
  const [simIp, setSimIp] = useState('203.0.113.88');
  const [simPath, setSimPath] = useState('/auth/login');
  const [simMethod, setSimMethod] = useState('POST');
  const [simResult, setSimResult] = useState(null);
  const [simulating, setSimulating] = useState(false);

  const fetchGatewayData = async () => {
    try {
      setLoading(true);
      const [s, conf, sessData] = await Promise.all([
        api.getGatewayStats(),
        api.getNginxConfig().catch(() => ''),
        api.getGatewaySessions().catch(() => ({ sessions: [], point_allocations: {} })),
      ]);
      setStats(s);
      setNginxConfig(conf);
      setSessions(sessData?.sessions || []);
      if (sessData?.point_allocations) {
        setPointAllocations(sessData.point_allocations);
      }
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

  const handleInspectSession = async (sess) => {
    setSelectedSession(sess);
    try {
      setLoadingDetail(true);
      const detail = await api.getGatewaySession(sess.session_id);
      setSessionDetail(detail);
    } catch (err) {
      setSessionDetail(sess);
    } finally {
      setLoadingDetail(false);
    }
  };

  const handleSimulate = async () => {
    try {
      setSimulating(true);
      const res = await api.simulateGatewayTraffic({
        src_ip: simIp,
        path: simPath,
        method: simMethod,
      });
      setSimResult(res);
      addToast(
        `Traffic evaluated: Routed to ${res.routed_to.toUpperCase()} (Score: ${res.risk_score.toFixed(1)})`,
        res.routed_to === 'decoy' ? 'warning' : 'info'
      );
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

  // Filtered Sessions
  const filteredSessions = useMemo(() => {
    return sessions.filter((s) => {
      const matchesSearch =
        !searchQuery ||
        s.session_id?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        s.src_ip?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        s.account_email?.toLowerCase().includes(searchQuery.toLowerCase());

      const matchesClass =
        classificationFilter === 'ALL' ||
        s.risk_classification?.toUpperCase() === classificationFilter;

      const matchesRoute =
        routeFilter === 'ALL' ||
        s.current_route?.toUpperCase() === routeFilter;

      return matchesSearch && matchesClass && matchesRoute;
    });
  }, [sessions, searchQuery, classificationFilter, routeFilter]);

  const defaultAllocations = {
    login_failures: { max: 12, label: 'Repeated login failures' },
    otp_failures: { max: 8, label: 'Repeated OTP failures' },
    password_reset_abuse: { max: 5, label: 'Password-reset abuse' },
    admin_access_attempts: { max: 15, label: 'Unauthorized admin access attempts' },
    secrets_code_probing: { max: 20, label: 'Source code, .env, secrets probing' },
    endpoint_enumeration: { max: 15, label: 'Sensitive endpoint enumeration' },
    abnormal_rate: { max: 10, label: 'Abnormal request frequency' },
    customer_db_access: { max: 10, label: 'Unauthorized customer/database access' },
    combined_patterns: { max: 5, label: 'Combined suspicious patterns (synergy)' },
  };

  const getClassificationBadge = (cls) => {
    switch (cls?.toUpperCase()) {
      case 'NORMAL':
        return 'bg-emerald-950/80 text-emerald-400 border-emerald-500/40';
      case 'SUSPICIOUS':
        return 'bg-amber-950/80 text-amber-400 border-amber-500/40';
      case 'HIGH_RISK':
        return 'bg-orange-950/80 text-orange-400 border-orange-500/40';
      case 'LIKELY_MALICIOUS':
        return 'bg-red-950/80 text-red-400 border-red-500/40 animate-pulse';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getScoreColor = (score) => {
    if (score < 30) return 'text-emerald-400';
    if (score < 50) return 'text-amber-400';
    if (score < 70) return 'text-orange-400';
    return 'text-red-400';
  };

  const getScoreBarBg = (score) => {
    if (score < 30) return 'bg-emerald-500';
    if (score < 50) return 'bg-amber-500';
    if (score < 70) return 'bg-orange-500';
    return 'bg-red-500';
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
                DECEPTION GATEWAY & 0–100 RISK SCORING ENGINE
                <span className="text-xs px-2 py-0.5 rounded bg-emerald-950 border border-emerald-500/40 text-emerald-300">
                  BEHAVIOURAL ROUTING
                </span>
              </h1>
              <p className="text-xs font-mono text-slate-400 mt-1">
                Continuous 0–100 behaviour-based risk engine with 9 category point allocations, time decay,
                and independent-category safeguards for automatic Decoy diversion.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => setShowAllocations(!showAllocations)}
            className="flex items-center space-x-2 px-3 py-2 bg-blue-900/30 hover:bg-blue-800/40 border border-blue-500/40 text-blue-300 rounded text-xs font-mono transition-all"
          >
            <Sliders className="w-3.5 h-3.5" />
            <span>{showAllocations ? 'Hide Point Model' : 'Point Model (100 pts)'}</span>
          </button>
          <button
            onClick={() => setShowConfig(!showConfig)}
            className="flex items-center space-x-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-white rounded text-xs font-mono transition-all"
          >
            <Layers className="w-3.5 h-3.5" />
            <span>{showConfig ? 'Hide NGINX' : 'NGINX Config'}</span>
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

      {/* Point Allocation Reference Card */}
      {showAllocations && (
        <div className="bg-slate-950 border border-blue-500/40 rounded-lg p-5 font-mono text-xs space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <span className="text-blue-400 font-bold flex items-center gap-2">
              <Sliders className="w-4 h-4" />
              0–100 Behaviour Point Allocation & Threshold Reference
            </span>
            <span className="text-[11px] text-slate-400">Sum = 100.0 Maximum Points</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {Object.entries(defaultAllocations).map(([k, item]) => {
              const maxVal = pointAllocations[k] !== undefined ? pointAllocations[k] : item.max;
              return (
                <div key={k} className="p-3 bg-slate-900 border border-slate-800 rounded flex justify-between items-center">
                  <div>
                    <div className="text-white font-medium">{item.label}</div>
                    <div className="text-[10px] text-slate-400 uppercase">{k}</div>
                  </div>
                  <div className="text-right">
                    <span className="text-sm font-bold text-blue-400">{maxVal}</span>
                    <span className="text-[10px] text-slate-500 block">max pts</span>
                  </div>
                </div>
              );
            })}
          </div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-2 pt-2 border-t border-slate-800 text-[11px]">
            <div className="p-2 bg-emerald-950/40 border border-emerald-500/30 rounded text-emerald-300">
              <span className="font-bold">0 – 29: NORMAL</span>
              <div className="text-[10px] text-slate-400">Real App (Trusted)</div>
            </div>
            <div className="p-2 bg-amber-950/40 border border-amber-500/30 rounded text-amber-300">
              <span className="font-bold">30 – 49: SUSPICIOUS</span>
              <div className="text-[10px] text-slate-400">Real App (Enhanced Monitoring)</div>
            </div>
            <div className="p-2 bg-orange-950/40 border border-orange-500/30 rounded text-orange-300">
              <span className="font-bold">50 – 69: HIGH_RISK</span>
              <div className="text-[10px] text-slate-400">Real App (Scrutiny / Alert)</div>
            </div>
            <div className="p-2 bg-red-950/40 border border-red-500/30 rounded text-red-300">
              <span className="font-bold">70 – 100: LIKELY_MALICIOUS</span>
              <div className="text-[10px] text-slate-400">Decoy (Req. ≥ 2 independent categories)</div>
            </div>
          </div>
        </div>
      )}

      {/* NGINX Config Viewer Modal */}
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
          <div className="text-[11px] font-mono text-slate-500 mt-1">Score: 0 – 69 (Real Workload)</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-2">
            <span>DECOY TRAFFIC (DIVERTED)</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-red-400">{stats?.decoy_traffic_count || 0}</div>
          <div className="text-[11px] font-mono text-slate-500 mt-1">Score: 70 – 100 (Decoy Honeynet)</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-2">
            <span>ACTIVE SESSIONS</span>
            <UserCheck className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400">{sessions.length}</div>
          <div className="text-[11px] font-mono text-slate-500 mt-1">Tracked visitor sessions</div>
        </div>
      </div>

      {/* Visitor Sessions & Behaviour Risk Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 font-mono space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <UserCheck className="w-4 h-4 text-blue-400" />
              Visitor Sessions & 0–100 Behaviour-Based Risk Profiles
            </h2>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Continuously calculated session threat scores, category contributions, and automated diversion status.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
              {filteredSessions.length} sessions
            </span>
          </div>
        </div>

        {/* Filter & Search Bar */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search by IP, Session, or Account..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-xs text-white placeholder-slate-500 focus:border-blue-500 outline-none"
            />
          </div>

          <div className="flex items-center gap-1.5 overflow-x-auto text-xs">
            <span className="text-slate-500 text-[11px]">Class:</span>
            {['ALL', 'NORMAL', 'SUSPICIOUS', 'HIGH_RISK', 'LIKELY_MALICIOUS'].map((c) => (
              <button
                key={c}
                onClick={() => setClassificationFilter(c)}
                className={`px-2 py-1 rounded text-[10px] font-bold transition-all border ${
                  classificationFilter === c
                    ? 'bg-blue-600 text-white border-blue-500'
                    : 'bg-slate-950 text-slate-400 border-slate-800 hover:border-slate-700'
                }`}
              >
                {c}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1.5 justify-end text-xs">
            <span className="text-slate-500 text-[11px]">Route:</span>
            {['ALL', 'REAL', 'DECOY'].map((r) => (
              <button
                key={r}
                onClick={() => setRouteFilter(r)}
                className={`px-2.5 py-1 rounded text-[10px] font-bold transition-all border ${
                  routeFilter === r
                    ? 'bg-blue-600 text-white border-blue-500'
                    : 'bg-slate-950 text-slate-400 border-slate-800 hover:border-slate-700'
                }`}
              >
                {r}
              </button>
            ))}
          </div>
        </div>

        {/* Sessions Table */}
        <div className="overflow-x-auto border border-slate-800 rounded-lg">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Session ID</th>
                <th className="py-2.5 px-3">Visitor IP</th>
                <th className="py-2.5 px-3">Account</th>
                <th className="py-2.5 px-3 text-center">Score (0–100)</th>
                <th className="py-2.5 px-3">Classification</th>
                <th className="py-2.5 px-3">Active Categories</th>
                <th className="py-2.5 px-3">Route</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredSessions.length === 0 ? (
                <tr>
                  <td colSpan={8} className="text-center py-8 text-slate-500">
                    No visitor sessions match the current filter. Interact with the demo apps or run the simulator.
                  </td>
                </tr>
              ) : (
                filteredSessions.map((sess) => {
                  const score = Number(sess.risk_score || 0);
                  const isDiverted = sess.is_diverted || sess.current_route === 'decoy';
                  return (
                    <tr
                      key={sess.session_id}
                      className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                      onClick={() => handleInspectSession(sess)}
                    >
                      <td className="py-2.5 px-3 font-mono text-slate-300">
                        <span className="text-blue-400 font-bold">{sess.session_id.slice(0, 16)}...</span>
                      </td>
                      <td className="py-2.5 px-3 font-mono text-slate-200">{sess.src_ip}</td>
                      <td className="py-2.5 px-3 text-slate-400">
                        {sess.account_email || <span className="text-slate-600 italic">anonymous</span>}
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="flex items-center space-x-2 justify-center">
                          <span className={`font-bold font-mono text-sm ${getScoreColor(score)}`}>
                            {score.toFixed(1)}
                          </span>
                          <div className="w-16 bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
                            <div
                              className={`h-full ${getScoreBarBg(score)} transition-all duration-300`}
                              style={{ width: `${Math.min(100, Math.max(0, score))}%` }}
                            />
                          </div>
                        </div>
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getClassificationBadge(
                            sess.risk_classification
                          )}`}
                        >
                          {sess.risk_classification || 'NORMAL'}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="px-1.5 py-0.5 bg-slate-800 border border-slate-700 rounded text-slate-300 text-[11px]">
                          {sess.independent_categories_count || (sess.active_categories ? Object.keys(sess.active_categories).length : 0)} active
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        {isDiverted ? (
                          <span className="px-2 py-0.5 bg-red-950 border border-red-500/50 text-red-400 rounded text-[10px] font-bold flex items-center gap-1 w-fit">
                            <ShieldAlert className="w-3 h-3 text-red-400" />
                            DECOY
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 bg-emerald-950 border border-emerald-500/50 text-emerald-400 rounded text-[10px] font-bold flex items-center gap-1 w-fit">
                            <CheckCircle className="w-3 h-3 text-emerald-400" />
                            REAL
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleInspectSession(sess);
                          }}
                          className="px-2 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded text-slate-300 hover:text-white text-[11px] flex items-center gap-1 ml-auto"
                        >
                          <Eye className="w-3 h-3" />
                          <span>Inspect</span>
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Session Detailed Inspection Modal */}
      {selectedSession && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-lg max-w-3xl w-full max-h-[90vh] flex flex-col font-mono text-xs overflow-hidden shadow-2xl">
            {/* Modal Header */}
            <div className="p-4 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <ShieldAlert className="w-5 h-5 text-blue-400" />
                <div>
                  <h3 className="text-white font-bold text-sm flex items-center gap-2">
                    Session Threat Inspection: {selectedSession.session_id.slice(0, 20)}...
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getClassificationBadge(
                        selectedSession.risk_classification
                      )}`}
                    >
                      {selectedSession.risk_classification}
                    </span>
                  </h3>
                  <div className="text-slate-400 text-[11px] flex items-center gap-3 mt-0.5">
                    <span>IP: <strong className="text-slate-200">{selectedSession.src_ip}</strong></span>
                    <span>Account: <strong className="text-slate-200">{selectedSession.account_email || 'anonymous'}</strong></span>
                    <span>Route: <strong className={selectedSession.is_diverted ? 'text-red-400' : 'text-emerald-400'}>
                      {selectedSession.is_diverted ? 'DECOY (DIVERTED)' : 'REAL APPLICATION'}
                    </strong></span>
                  </div>
                </div>
              </div>
              <button
                onClick={() => setSelectedSession(null)}
                className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-5 space-y-5 overflow-y-auto flex-1">
              {/* Overall Score Gauge Card */}
              <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg flex items-center justify-between">
                <div>
                  <span className="text-slate-400 text-[11px] block">TOTAL BEHAVIOUR RISK SCORE</span>
                  <div className="flex items-baseline space-x-2 mt-1">
                    <span className={`text-3xl font-bold ${getScoreColor(selectedSession.risk_score)}`}>
                      {Number(selectedSession.risk_score || 0).toFixed(2)}
                    </span>
                    <span className="text-slate-500 text-sm">/ 100.0 max</span>
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">
                    Independent Hostile Categories: <strong>{selectedSession.independent_categories_count || 0}</strong> (Decoy requires ≥ 2 & score ≥ 70)
                  </div>
                </div>
                <div className="text-right">
                  {selectedSession.is_diverted ? (
                    <div className="p-2.5 bg-red-950/60 border border-red-500/50 rounded text-red-300">
                      <div className="font-bold flex items-center gap-1.5 justify-end">
                        <ShieldAlert className="w-4 h-4 text-red-400" />
                        DIVERTED TO HONEYPOT
                      </div>
                      <div className="text-[10px] text-red-400 mt-1">{selectedSession.diversion_reason}</div>
                    </div>
                  ) : (
                    <div className="p-2.5 bg-emerald-950/60 border border-emerald-500/50 rounded text-emerald-300">
                      <div className="font-bold flex items-center gap-1.5 justify-end">
                        <CheckCircle className="w-4 h-4 text-emerald-400" />
                        ROUTED TO REAL APP
                      </div>
                      <div className="text-[10px] text-emerald-400 mt-1">Within normal/scrutiny thresholds</div>
                    </div>
                  )}
                </div>
              </div>

              {/* 9 Category Breakdown */}
              <div className="space-y-2">
                <h4 className="text-white font-bold text-xs flex items-center justify-between">
                  <span>9-BEHAVIOUR CATEGORY CONTRIBUTION BREAKDOWN</span>
                  <span className="text-slate-400 text-[10px]">Max 100.0 pts</span>
                </h4>
                <div className="space-y-2">
                  {Object.entries(defaultAllocations).map(([catKey, catInfo]) => {
                    const catScoreObj = selectedSession.category_scores?.[catKey] || {};
                    const contribution = Number(catScoreObj.contribution || 0);
                    const severity = Number(catScoreObj.severity || 0);
                    const maxPts = pointAllocations[catKey] !== undefined ? pointAllocations[catKey] : catInfo.max;
                    const isActive = contribution > 0 || severity > 0;

                    return (
                      <div
                        key={catKey}
                        className={`p-2.5 rounded border transition-all ${
                          isActive
                            ? 'bg-slate-950 border-slate-700'
                            : 'bg-slate-950/40 border-slate-900 opacity-60'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-2">
                            <span
                              className={`w-2 h-2 rounded-full ${
                                isActive ? 'bg-amber-400' : 'bg-slate-600'
                              }`}
                            />
                            <span className="text-slate-200 font-medium">{catInfo.label}</span>
                            <span className="text-[10px] text-slate-500">({catKey})</span>
                          </div>
                          <div className="text-right flex items-center space-x-3">
                            <span className="text-[11px] text-slate-400">
                              Severity: <strong className="text-white">{severity.toFixed(1)}%</strong>
                            </span>
                            <span className="text-xs font-bold font-mono text-blue-400">
                              {contribution.toFixed(2)} / {maxPts} pts
                            </span>
                          </div>
                        </div>

                        {/* Mini progress bar */}
                        <div className="mt-2 w-full bg-slate-900 rounded-full h-1.5 overflow-hidden">
                          <div
                            className="h-full bg-blue-500 transition-all duration-300"
                            style={{
                              width: `${Math.min(100, (contribution / maxPts) * 100)}%`,
                            }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Reason Codes */}
              {selectedSession.reason_codes && selectedSession.reason_codes.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-white font-bold text-xs">TRIGGERED REASON CODES</h4>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedSession.reason_codes.map((code, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-1 rounded bg-slate-950 border border-slate-700 text-slate-300 text-[11px]"
                      >
                        {code}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Routing Transition History */}
              {selectedSession.routing_transitions && selectedSession.routing_transitions.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-white font-bold text-xs flex items-center gap-1.5">
                    <History className="w-3.5 h-3.5 text-blue-400" />
                    ROUTING TRANSITION TIMELINE
                  </h4>
                  <div className="space-y-1.5">
                    {selectedSession.routing_transitions.map((tr, idx) => (
                      <div
                        key={idx}
                        className="p-2 rounded bg-slate-950 border border-slate-800 text-[11px] flex items-center justify-between"
                      >
                        <div className="flex items-center space-x-2">
                          <span className="font-bold text-slate-300">
                            {tr.from_route?.toUpperCase()} → {tr.to_route?.toUpperCase()}
                          </span>
                          <span className="text-slate-500">at risk score {tr.risk_score}</span>
                        </div>
                        <div className="text-slate-400 text-[10px]">
                          {tr.timestamp ? new Date(tr.timestamp).toLocaleTimeString() : 'recorded'}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="p-3 bg-slate-950 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedSession(null)}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded text-xs"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}

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
            <div>• <span className="text-emerald-400 font-bold">0 – 29 pts:</span> Routed directly to Real Application workload.</div>
            <div>• <span className="text-amber-400 font-bold">30 – 49 pts:</span> Enhanced monitoring on Real Application.</div>
            <div>• <span className="text-orange-400 font-bold">50 – 69 pts:</span> High-risk scrutiny on Real Application.</div>
            <div>• <span className="text-red-400 font-bold">70 – 100 pts:</span> Seamlessly diverted to isolated Decoy (requires ≥ 2 categories).</div>
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
