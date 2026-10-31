import React, { useState } from 'react';
import {
  ShieldAlert,
  Zap,
  Activity,
  Layers,
  Clock,
  TrendingUp,
  AlertTriangle,
  Play,
  CheckCircle,
  ExternalLink,
  Lock,
  Database,
  KeyRound,
  CreditCard,
  UserCheck,
  FileCode,
  ShieldCheck,
  RotateCcw,
  FlaskConical,
  Eye,
} from 'lucide-react';
import { useSoc } from '../context/SocContext';
import { api } from '../api/client';

export default function FunctionIntelligencePage() {
  const {
    functionStats,
    functionEvents,
    refreshFunctionStats,
    setSelectedAttackerId,
    blockAttacker,
    addToast,
  } = useSoc();

  const [simulating, setSimulating] = useState(false);
  const [selectedFuncFilter, setSelectedFuncFilter] = useState('all');
  const [sourceFilter, setSourceFilter] = useState('all'); // all, observed, simulated

  const metadata = functionStats?.metadata || {};
  const mostTargeted = functionStats?.most_targeted_functions || [];
  const topAttackers = functionStats?.top_attackers || [];
  const totalEvents = functionStats?.total_targeted_events || 0;
  const observedEvents = functionStats?.observed_events_count || 0;
  const simulatedEvents = functionStats?.simulated_events_count || 0;

  const getFunctionIcon = (key) => {
    switch (key) {
      case 'auth_login':
        return UserCheck;
      case 'auth_otp':
        return KeyRound;
      case 'auth_reset':
        return RotateCcw;
      case 'admin_access':
        return ShieldAlert;
      case 'payment_gateway':
        return CreditCard;
      case 'database_api':
        return Database;
      case 'secrets_env':
        return FileCode;
      default:
        return Zap;
    }
  };

  const getRiskBandBadge = (band, score) => {
    let colorClasses = 'bg-emerald-950 text-emerald-400 border-emerald-500/50';
    if (band === 'high' || score >= 70) {
      colorClasses = 'bg-red-950 text-red-400 border-red-500/50';
    } else if (band === 'medium' || score >= 30) {
      colorClasses = 'bg-yellow-950 text-yellow-400 border-yellow-500/50';
    }
    return (
      <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold border uppercase ${colorClasses}`}>
        {band || 'low'} ({score ? score.toFixed(1) : '0.0'})
      </span>
    );
  };

  const handleSimulateAttack = async (scenarioType) => {
    setSimulating(true);
    try {
      const testIps = ['198.51.100.89', '203.0.113.14', '192.0.2.77'];
      const ip = testIps[Math.floor(Math.random() * testIps.length)];

      if (scenarioType === 'credential_synergy') {
        // Step 1: Login attempt
        await api.simulateFunctionTargeting({
          src_ip: ip,
          target_function: 'auth_login',
          target_endpoint: '/api/v1/auth/login',
          attack_type: 'brute_force',
          severity: 'medium',
          attempts: 4,
          evidence: '[Simulated] Credential stuffing probe targeting login endpoint',
          is_simulated: true,
        });
        // Step 2: OTP bypass attempt within 5 seconds
        await api.simulateFunctionTargeting({
          src_ip: ip,
          target_function: 'auth_otp',
          target_endpoint: '/api/v1/auth/otp/verify',
          attack_type: 'otp_bypass',
          severity: 'high',
          attempts: 2,
          evidence: '[Simulated] 6-digit OTP token bypass attempt (Synergy bonus triggered)',
          is_simulated: true,
        });
        addToast(`Simulated Credential -> 2FA Bypass synergy on ${ip}`, 'warning');
      } else if (scenarioType === 'privesc_payment') {
        // Admin Access then Payment Gateway
        await api.simulateFunctionTargeting({
          src_ip: ip,
          target_function: 'admin_access',
          target_endpoint: '/admin/privilege/escalate',
          attack_type: 'privilege_escalation',
          severity: 'high',
          attempts: 1,
          evidence: '[Simulated] Parameter pollution targeting admin privilege endpoint',
          is_simulated: true,
        });
        await api.simulateFunctionTargeting({
          src_ip: ip,
          target_function: 'payment_gateway',
          target_endpoint: '/api/v1/checkout/stripe/refund',
          attack_type: 'fraud_injection',
          severity: 'critical',
          attempts: 2,
          evidence: '[Simulated] Unverified refund dispatch targeting payment gateway',
          is_simulated: true,
        });
        addToast(`Simulated Admin Escalation -> Payment Gateway attack on ${ip}`, 'error');
      } else {
        // Secrets Env Probe
        await api.simulateFunctionTargeting({
          src_ip: ip,
          target_function: 'secrets_env',
          target_endpoint: '/.env',
          attack_type: 'sensitive_file_read',
          severity: 'high',
          attempts: 1,
          evidence: '[Simulated] Direct HTTP probe requesting production environment secrets',
          is_simulated: true,
        });
        addToast(`Simulated Secrets & Environment probe on ${ip}`, 'info');
      }

      await refreshFunctionStats();
    } catch (err) {
      console.error(err);
      if (err.message && err.message.includes('401')) {
        addToast('Simulation failed: HTTP 401 Unauthorized (X-API-Key required for simulation injection)', 'error');
      } else {
        addToast(`Simulation error: ${err.message}`, 'error');
      }
    } finally {
      setSimulating(false);
    }
  };

  const filteredEvents = functionEvents.filter((ev) => {
    if (selectedFuncFilter !== 'all' && ev.target_function !== selectedFuncFilter) return false;
    if (sourceFilter === 'observed' && ev.is_simulated) return false;
    if (sourceFilter === 'simulated' && !ev.is_simulated) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Page Title & USP Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-lg p-5">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-red-950/60 border border-red-500/40 rounded-lg text-red-400">
              <Zap className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <h1 className="text-xl font-bold font-mono text-white tracking-wider flex items-center gap-2">
                LEVEL-2 BEHAVIOURAL FUNCTION PROFILING
                <span className="text-xs px-2 py-0.5 rounded bg-blue-950 border border-blue-500/40 text-blue-300">
                  CORE DIFFERENTIATOR
                </span>
              </h1>
              <p className="text-xs font-mono text-slate-400 mt-1">
                Beyond generic MITRE / Kill-Chain signatures: Identifying which critical system functions are targeted,
                detecting attack synergies, and computing bounded explainable risk scores [0 - 100].
              </p>
            </div>
          </div>
        </div>

        {/* Action / Simulation Trigger */}
        <div className="flex items-center space-x-2">
          <button
            onClick={() => handleSimulateAttack('credential_synergy')}
            disabled={simulating}
            className="flex items-center space-x-2 px-3 py-2 bg-red-900/60 hover:bg-red-800 border border-red-600/60 text-white rounded text-xs font-mono transition-all disabled:opacity-50"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>{simulating ? 'Injecting...' : 'Simulate 2FA Synergy'}</span>
          </button>
          <button
            onClick={() => handleSimulateAttack('privesc_payment')}
            disabled={simulating}
            className="flex items-center space-x-2 px-3 py-2 bg-amber-900/60 hover:bg-amber-800 border border-amber-600/60 text-white rounded text-xs font-mono transition-all disabled:opacity-50"
          >
            <TrendingUp className="w-3.5 h-3.5" />
            <span>Admin-Payment Synergy</span>
          </button>
          <button
            onClick={refreshFunctionStats}
            className="p-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 rounded text-xs font-mono transition-all"
            title="Refresh Intelligence"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Top Metrics Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-2">
            <span>CRITICAL FUNCTIONS</span>
            <Layers className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">7 Active</div>
          <div className="text-[11px] font-mono text-slate-500 mt-1">Auth, Admin, Financial, Core Data</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-2">
            <span>INTERCEPTED ATTEMPTS</span>
            <Activity className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-red-400">{totalEvents}</div>
          <div className="text-[11px] font-mono text-slate-500 mt-1">
            Observed: <span className="text-emerald-400 font-bold">{observedEvents}</span> | Sim: <span className="text-purple-400 font-bold">{simulatedEvents}</span>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-2">
            <span>MULTI-FUNCTION THREATS</span>
            <ShieldAlert className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400">
            {topAttackers.filter((a) => (a.targeted_functions?.length || 0) > 1).length}
          </div>
          <div className="text-[11px] font-mono text-slate-500 mt-1">Attackers targeting ≥2 functions</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-2">
            <span>SCORING ENGINE</span>
            <Clock className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">Bounded [0-100]</div>
          <div className="text-[11px] font-mono text-slate-500 mt-1">Sliding windows: 30s - 15m</div>
        </div>
      </div>

      {/* 7 Targetable Functions Showcase */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-bold font-mono text-slate-300 uppercase tracking-wider flex items-center gap-2">
            <Layers className="w-4 h-4 text-blue-400" />
            Sensitive Target Functions Grid ({mostTargeted.length || 7})
          </h2>
          <div className="flex items-center space-x-1">
            <button
              onClick={() => setSelectedFuncFilter('all')}
              className={`px-2 py-1 text-xs font-mono rounded ${
                selectedFuncFilter === 'all'
                  ? 'bg-blue-600 text-white font-bold'
                  : 'bg-slate-800 text-slate-400 hover:text-white'
              }`}
            >
              All
            </button>
            {mostTargeted.map((f) => (
              <button
                key={f.key}
                onClick={() => setSelectedFuncFilter(f.key)}
                className={`px-2 py-1 text-xs font-mono rounded ${
                  selectedFuncFilter === f.key
                    ? 'bg-blue-600 text-white font-bold'
                    : 'bg-slate-800 text-slate-400 hover:text-white'
                }`}
              >
                {f.key.replace('auth_', '').replace('_', ' ')}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
          {mostTargeted.map((f) => {
            const Icon = getFunctionIcon(f.key);
            const isSelected = selectedFuncFilter === f.key;
            return (
              <div
                key={f.key}
                onClick={() => setSelectedFuncFilter(isSelected ? 'all' : f.key)}
                className={`bg-slate-900 border rounded-lg p-4 transition-all cursor-pointer relative overflow-hidden ${
                  isSelected
                    ? 'border-blue-500 shadow-lg shadow-blue-500/10 ring-1 ring-blue-500/50'
                    : 'border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-start justify-between">
                  <div className="p-2 bg-slate-800/80 rounded border border-slate-700 text-blue-400">
                    <Icon className="w-5 h-5" />
                  </div>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                    {f.category}
                  </span>
                </div>

                <div className="mt-3">
                  <div className="text-sm font-bold font-mono text-white truncate">{f.name}</div>
                  <div className="text-[11px] font-mono text-slate-500 mt-0.5">{metadata[f.key]?.description || ''}</div>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
                  <div className="text-slate-400">
                    Base Weight: <span className="font-bold text-amber-400">{f.weight}</span>
                  </div>
                  <div className="text-slate-400">
                    Attempts: <span className="font-bold text-red-400">{f.attempts}</span>
                  </div>
                </div>

                {/* Gauge bar */}
                <div className="mt-2 w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${f.attempts > 0 ? 'bg-red-500' : 'bg-slate-700'}`}
                    style={{ width: `${Math.min(100, Math.max(10, f.attempts * 15))}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Main Two-Column View: Top Attackers & Real-Time Function Sequence Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Top Function-Targeting Attackers */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-bold font-mono text-white uppercase tracking-wider flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              Top Function-Level Attackers
            </h2>
            <span className="text-xs font-mono text-slate-400">Bounded Risk [0-100]</span>
          </div>

          <div className="space-y-3 flex-1 overflow-y-auto max-h-[500px]">
            {topAttackers.length === 0 ? (
              <div className="text-center py-12 text-xs font-mono text-slate-500">
                No high-risk function targeting recorded yet. Use the simulation buttons above to test live calculation.
              </div>
            ) : (
              topAttackers.map((atk) => (
                <div
                  key={atk.id}
                  className="bg-slate-950/70 border border-slate-800/80 rounded-lg p-3 hover:border-slate-700 transition-all font-mono"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <span className="font-bold text-sm text-slate-200">{atk.ip}</span>
                      {atk.is_simulated && (
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-purple-950 border border-purple-500/40 text-purple-300">
                          SIMULATED
                        </span>
                      )}
                      <button
                        onClick={() => setSelectedAttackerId(atk.id)}
                        className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1"
                        title="Investigate Profile"
                      >
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    </div>
                    <div>{getRiskBandBadge(atk.risk_band, atk.function_risk_score)}</div>
                  </div>

                  <div className="mt-2 flex flex-wrap gap-1.5 items-center">
                    <span className="text-[11px] text-slate-400">Targeted:</span>
                    {(atk.targeted_functions || []).map((fn) => (
                      <span
                        key={fn}
                        className="text-[10px] px-1.5 py-0.5 rounded bg-blue-950 border border-blue-500/30 text-blue-300"
                      >
                        {fn}
                      </span>
                    ))}
                  </div>

                  {atk.explanation && (
                    <div className="mt-2 text-[11px] text-slate-400 bg-slate-900/60 p-2 rounded border border-slate-800">
                      {atk.explanation}
                    </div>
                  )}

                  <div className="mt-2 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-slate-500">
                    <span>Sequence Window: {atk.time_window_seconds ? `${atk.time_window_seconds}s` : 'single'}</span>
                    <button
                      onClick={() => blockAttacker(atk.ip, 'Critical function attack synergy threshold exceeded')}
                      className="px-2 py-0.5 bg-red-950 hover:bg-red-900 text-red-300 border border-red-500/40 rounded text-[10px] flex items-center gap-1"
                    >
                      <Lock className="w-3 h-3" />
                      Block IP
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right: Real-time Function Targeting Sequence Feed */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-bold font-mono text-white uppercase tracking-wider flex items-center gap-2">
              <Activity className="w-4 h-4 text-emerald-400" />
              Real-Time Function Interception Feed
            </h2>
            {/* Source Filter: All / Observed / Simulated */}
            <div className="flex items-center space-x-1 bg-slate-950 border border-slate-800 rounded p-0.5">
              <button
                onClick={() => setSourceFilter('all')}
                className={`px-2 py-0.5 text-[10px] font-mono rounded ${
                  sourceFilter === 'all' ? 'bg-blue-600 text-white font-bold' : 'text-slate-400 hover:text-white'
                }`}
              >
                All
              </button>
              <button
                onClick={() => setSourceFilter('observed')}
                className={`px-2 py-0.5 text-[10px] font-mono rounded flex items-center gap-1 ${
                  sourceFilter === 'observed' ? 'bg-emerald-700 text-white font-bold' : 'text-slate-400 hover:text-white'
                }`}
              >
                <Eye className="w-2.5 h-2.5" />
                Observed
              </button>
              <button
                onClick={() => setSourceFilter('simulated')}
                className={`px-2 py-0.5 text-[10px] font-mono rounded flex items-center gap-1 ${
                  sourceFilter === 'simulated' ? 'bg-purple-700 text-white font-bold' : 'text-slate-400 hover:text-white'
                }`}
              >
                <FlaskConical className="w-2.5 h-2.5" />
                Simulated
              </button>
            </div>
          </div>

          <div className="space-y-2.5 flex-1 overflow-y-auto max-h-[500px]">
            {filteredEvents.length === 0 ? (
              <div className="text-center py-12 text-xs font-mono text-slate-500">
                No function targeting events matching current filter.
              </div>
            ) : (
              filteredEvents.slice(0, 30).map((ev) => (
                <div
                  key={ev.id || `${ev.src_ip}-${ev.timestamp}`}
                  className="bg-slate-950/60 border border-slate-800/80 rounded p-3 font-mono text-xs hover:border-slate-700 transition-all"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <span className="font-bold text-slate-200">{ev.src_ip}</span>
                      <span className="text-slate-500">&rarr;</span>
                      <span className="text-amber-400 font-bold">{ev.target_function}</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      {ev.is_simulated ? (
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-500/40 font-bold flex items-center gap-1">
                          <FlaskConical className="w-2.5 h-2.5" />
                          SIMULATED
                        </span>
                      ) : (
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-500/40 font-bold flex items-center gap-1">
                          <Eye className="w-2.5 h-2.5" />
                          OBSERVED ({Math.round((ev.confidence || 0.9) * 100)}%)
                        </span>
                      )}
                      <span className="text-[10px] text-slate-500">
                        {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : 'now'}
                      </span>
                    </div>
                  </div>

                  <div className="mt-1 text-slate-400 text-[11px] truncate">
                    Endpoint: <span className="text-slate-300">{ev.target_endpoint || `/${ev.target_function}`}</span>
                  </div>

                  {ev.evidence && (
                    <div className="mt-1 text-[11px] text-slate-400 italic bg-slate-900/40 p-1.5 rounded">
                      &ldquo;{ev.evidence}&rdquo;
                    </div>
                  )}

                  <div className="mt-2 pt-1.5 border-t border-slate-800/60 flex items-center justify-between text-[10px] text-slate-500">
                    <span>Source: {ev.honeypot_source || 'gateway'}</span>
                    <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      {ev.attack_type || 'probe'} ({ev.attempts || 1} att)
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Explanatory Engine Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 font-mono">
        <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-2 flex items-center gap-2">
          <TrendingUp className="w-4 h-4 text-purple-400" />
          Explainable & Bounded Scoring Architecture
        </h3>
        <p className="text-xs text-slate-400 mb-3 leading-relaxed">
          Unlike black-box models or unbounded scoring multipliers, SENTINEL computes Level-2 Function Risk using
          explainable parameters capped strictly at 100.0:
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          <div className="bg-slate-950 p-3 rounded border border-slate-800">
            <div className="font-bold text-blue-400 mb-1">1. Base Impact (≤60 pts)</div>
            <p className="text-slate-400 text-[11px]">
              Maximum function weight + 0.35 &times; breadth expansion. Avoids linear accumulation while penalizing multi-target breadth.
            </p>
          </div>
          <div className="bg-slate-950 p-3 rounded border border-slate-800">
            <div className="font-bold text-amber-400 mb-1">2. Canonical Synergies (≤25 pts)</div>
            <p className="text-slate-400 text-[11px]">
              Specific high-risk sequences: Login &rarr; OTP (+8), Login &rarr; Admin (+10), Admin &rarr; Payment/DB (+15), Config Leaks (+12).
            </p>
          </div>
          <div className="bg-slate-950 p-3 rounded border border-slate-800">
            <div className="font-bold text-emerald-400 mb-1">3. Temporal Multiplier (1.0x - 1.45x)</div>
            <p className="text-slate-400 text-[11px]">
              Sliding windows: &le;30s (1.45x), &le;60s (1.30x), &le;5m (1.20x), &le;15m (1.10x). Distinguishes rapid automated attacks from casual probes.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
