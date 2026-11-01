import React, { useState, useEffect, useMemo } from 'react';
import {
  ShieldAlert,
  Zap,
  Activity,
  Layers,
  CheckCircle,
  ExternalLink,
  Lock,
  Database,
  KeyRound,
  CreditCard,
  UserCheck,
  FileCode,
  RotateCcw,
  FlaskConical,
  Eye,
  Square,
  Repeat,
  Wifi,
  WifiOff,
  Crosshair,
  Server,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { useSoc } from '../context/SocContext';
import { api } from '../api/client';

const DEFAULT_FUNCTIONS = [
  { key: 'auth_login', name: 'Login / Authentication', category: 'Authentication', weight: 45, attempts: 0 },
  { key: 'secrets_env', name: 'Configuration & Secrets (.env)', category: 'Configuration', weight: 55, attempts: 0 },
  { key: 'admin_access', name: 'Admin / Privilege Access', category: 'Administration', weight: 50, attempts: 0 },
  { key: 'database_api', name: 'Database & Query Endpoints', category: 'Database', weight: 40, attempts: 0 },
  { key: 'auth_otp', name: 'Two-Factor Auth / OTP', category: 'Authentication', weight: 35, attempts: 0 },
  { key: 'payment_gateway', name: 'Payment Gateway / Transactions', category: 'Payment', weight: 45, attempts: 0 },
  { key: 'auth_reset', name: 'Password Reset / Recovery', category: 'Account Recovery', weight: 30, attempts: 0 },
];

export default function FunctionIntelligencePage() {
  const {
    functionStats,
    functionEvents,
    refreshFunctionStats,
    refreshPagerdutyData,
    setSelectedAttackerId,
    blockAttacker,
    addToast,
    isLiveConnected,
    backendError,
  } = useSoc();

  // Demonstration control state
  const [demoSessionId] = useState('demo_fn_session_interactive');
  const [targetFunction, setTargetFunction] = useState('auth_login');
  const [activeAction, setActiveAction] = useState(null);
  const [isSimRunning, setIsSimRunning] = useState(false);
  const [lastResult, setLastResult] = useState(null);
  const [actionError, setActionError] = useState(null);

  // Filters & UI state
  const [selectedFuncFilter, setSelectedFuncFilter] = useState('all');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [sourceFilter, setSourceFilter] = useState('all'); // all, observed, simulated
  const [expandedAttackerId, setExpandedAttackerId] = useState(null);

  const mostTargeted = functionStats?.most_targeted_functions || [];
  const topAttackers = functionStats?.top_attackers || [];
  const totalEvents = functionStats?.total_targeted_events || 0;
  const observedEvents = functionStats?.observed_events_count || 0;
  const simulatedEvents = functionStats?.simulated_events_count || 0;

  // Poll demo status when simulation is streaming
  useEffect(() => {
    let timer;
    if (isSimRunning) {
      timer = setInterval(async () => {
        try {
          const status = await api.getFunctionDemoStatus(demoSessionId);
          if (!status.is_running && isSimRunning) {
            setIsSimRunning(false);
          }
        } catch {
          // Non-fatal polling error
        }
      }, 1500);
    }
    return () => clearInterval(timer);
  }, [isSimRunning, demoSessionId]);

  const displayFunctions = useMemo(() => {
    if (mostTargeted && mostTargeted.length > 0) return mostTargeted;
    return DEFAULT_FUNCTIONS;
  }, [mostTargeted]);

  const categories = useMemo(() => {
    const set = new Set(displayFunctions.map((f) => f.category || 'General'));
    return ['all', ...Array.from(set)];
  }, [displayFunctions]);

  const filteredFunctions = useMemo(() => {
    return displayFunctions.filter((f) => {
      if (selectedCategory !== 'all' && f.category !== selectedCategory) return false;
      if (selectedFuncFilter !== 'all' && f.key !== selectedFuncFilter) return false;
      return true;
    });
  }, [displayFunctions, selectedCategory, selectedFuncFilter]);

  // Derived Average Risk Score KPI
  const averageRiskScore = useMemo(() => {
    if (!topAttackers || topAttackers.length === 0) return '0.0';
    const sum = topAttackers.reduce((acc, a) => acc + (a.function_risk_score || 0), 0);
    return (sum / topAttackers.length).toFixed(1);
  }, [topAttackers]);

  const multiFunctionThreatsCount = useMemo(() => {
    return topAttackers.filter((a) => (a.targeted_functions?.length || 0) > 1).length;
  }, [topAttackers]);

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
    let colorClasses = 'bg-emerald-950/60 text-emerald-300 border-emerald-800/80';
    if (band === 'high' || band === 'critical' || score >= 70) {
      colorClasses = 'bg-rose-950/60 text-rose-300 border-rose-800/80';
    } else if (band === 'medium' || score >= 30) {
      colorClasses = 'bg-amber-950/60 text-amber-300 border-amber-800/80';
    }
    return (
      <span className={`px-2 py-0.5 rounded text-[11px] font-mono font-semibold border uppercase ${colorClasses}`}>
        {band || 'low'} ({score != null ? score.toFixed(1) : '0.0'})
      </span>
    );
  };

  // --------------------------------------------------------------------------
  // Simulation Handlers
  // --------------------------------------------------------------------------
  const handleNormalAccess = async () => {
    setActiveAction('normal');
    setActionError(null);
    try {
      const res = await api.triggerFunctionDemoAction({
        action: 'normal',
        target_function: targetFunction,
        session_id: demoSessionId,
      });
      setLastResult(res);
      addToast(`Normal Access: ${res.function_name} evaluated (Score: ${res.function_risk_score.toFixed(1)})`, 'info');
      await refreshFunctionStats();
    } catch (err) {
      setActionError(err.message || 'Failed to trigger Normal Access');
      addToast(`Error: ${err.message}`, 'error');
    } finally {
      setActiveAction(null);
    }
  };

  const handleRepeatedAccess = async () => {
    setActiveAction('repeated');
    setActionError(null);
    try {
      const res = await api.triggerFunctionDemoAction({
        action: 'repeated',
        target_function: targetFunction,
        session_id: demoSessionId,
      });
      setLastResult(res);
      addToast(`Repeated Access: ${res.function_name} (Attempts: ${res.attempts}) alert sent`, 'warning');
      if (refreshPagerdutyData) refreshPagerdutyData();
      await refreshFunctionStats();
    } catch (err) {
      setActionError(err.message || 'Failed to trigger Repeated Access');
      addToast(`Error: ${err.message}`, 'error');
    } finally {
      setActiveAction(null);
    }
  };

  const handleSensitiveProbe = async () => {
    setActiveAction('sensitive');
    setActionError(null);
    try {
      const res = await api.triggerFunctionDemoAction({
        action: 'sensitive_probe',
        target_function: targetFunction === 'auth_login' ? 'secrets_env' : targetFunction,
        session_id: demoSessionId,
      });
      setLastResult(res);
      addToast(`Sensitive Probe: ${res.function_name} alert dispatched`, 'error');
      if (refreshPagerdutyData) refreshPagerdutyData();
      await refreshFunctionStats();
    } catch (err) {
      setActionError(err.message || 'Failed to trigger Sensitive Probe');
      addToast(`Error: ${err.message}`, 'error');
    } finally {
      setActiveAction(null);
    }
  };

  const handleMultiRecon = async () => {
    setActiveAction('recon');
    setIsSimRunning(true);
    setActionError(null);
    try {
      const res = await api.triggerFunctionDemoRecon({ session_id: demoSessionId });
      setLastResult(res);
      addToast('Multi-Function Reconnaissance sequence streaming...', 'warning');
      setTimeout(() => {
        refreshFunctionStats();
        if (refreshPagerdutyData) refreshPagerdutyData();
      }, 1200);
      setTimeout(() => refreshFunctionStats(), 2200);
    } catch (err) {
      setActionError(err.message || 'Failed to trigger Multi-Function Recon');
      setIsSimRunning(false);
      addToast(`Error: ${err.message}`, 'error');
    } finally {
      setActiveAction(null);
    }
  };

  const handleStopSimulation = async () => {
    setActiveAction('stop');
    setActionError(null);
    try {
      const res = await api.stopFunctionDemo({ session_id: demoSessionId });
      setIsSimRunning(false);
      setLastResult(res);
      addToast('Simulation halted.', 'info');
      await refreshFunctionStats();
    } catch (err) {
      setActionError(err.message || 'Failed to stop simulation');
      addToast(`Error: ${err.message}`, 'error');
    } finally {
      setActiveAction(null);
    }
  };

  const handleResetDemoSession = async () => {
    setActiveAction('reset');
    setActionError(null);
    try {
      const res = await api.resetFunctionDemo({ session_id: demoSessionId });
      setIsSimRunning(false);
      setLastResult(res);
      addToast('Demo session reset to baseline 0.', 'info');
      await refreshFunctionStats();
    } catch (err) {
      setActionError(err.message || 'Failed to reset demo session');
      addToast(`Error: ${err.message}`, 'error');
    } finally {
      setActiveAction(null);
    }
  };

  const filteredEvents = functionEvents.filter((ev) => {
    if (selectedFuncFilter !== 'all' && ev.target_function !== selectedFuncFilter) return false;
    if (sourceFilter === 'observed' && ev.is_simulated) return false;
    if (sourceFilter === 'simulated' && !ev.is_simulated) return false;
    return true;
  });

  return (
    <div className="space-y-4 font-sans text-slate-300 pb-10">
      {/* ------------------------------------------------------------------ */}
      {/* 1. COMPACT HEADER                                                 */}
      {/* ------------------------------------------------------------------ */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div>
          <h1 className="text-base font-semibold text-slate-100 tracking-wide font-mono">
            Function Intelligence
          </h1>
          <p className="text-xs text-slate-400 mt-0.5 font-mono">
            Monitor and analyze attacks targeting critical application functions.
          </p>
        </div>

        <div className="flex items-center space-x-2.5">
          <div
            className={`inline-flex items-center space-x-1.5 px-2.5 py-1 rounded text-xs font-mono border ${
              isLiveConnected
                ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-400'
                : 'bg-rose-950/40 border-rose-800/60 text-rose-400'
            }`}
          >
            {isLiveConnected ? (
              <>
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                <Wifi className="w-3.5 h-3.5" />
                <span>Live Telemetry</span>
              </>
            ) : (
              <>
                <WifiOff className="w-3.5 h-3.5" />
                <span>Offline</span>
              </>
            )}
          </div>

          <button
            onClick={refreshFunctionStats}
            className="flex items-center space-x-1.5 px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-white font-mono text-xs transition"
            title="Refresh telemetry"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Error alert banner if any */}
      {(!isLiveConnected || actionError || backendError) && (
        <div className="bg-rose-950/40 border border-rose-800/70 rounded p-2.5 text-xs font-mono text-rose-300 flex items-start justify-between">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>
              {actionError || (!isLiveConnected ? 'WebSocket telemetry stream disconnected.' : backendError)}
            </span>
          </div>
          {actionError && (
            <button
              onClick={() => setActionError(null)}
              className="text-rose-400 hover:text-white underline text-xs ml-2 shrink-0"
            >
              Dismiss
            </button>
          )}
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* 2. COMPACT CONTROL PANEL: SIMULATION ACTIONS                      */}
      {/* ------------------------------------------------------------------ */}
      <div className="rounded-lg bg-slate-900/70 border border-slate-800 p-3.5 space-y-3">
        {/* Top Control Bar: Function Target Selector & Metadata */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-2.5 pb-2.5 border-b border-slate-800/80 text-xs font-mono">
          <div className="flex items-center space-x-2 flex-wrap gap-y-1">
            <span className="text-slate-400 font-medium flex items-center gap-1.5">
              <Crosshair className="w-3.5 h-3.5 text-cyan-400" />
              Target:
            </span>
            <div className="flex items-center space-x-1 flex-wrap gap-1">
              {[
                { key: 'auth_login', name: 'Login' },
                { key: 'auth_otp', name: 'OTP' },
                { key: 'admin_access', name: 'Admin' },
                { key: 'payment_gateway', name: 'Payment' },
                { key: 'database_api', name: 'Database' },
                { key: 'secrets_env', name: 'Secrets' },
                { key: 'auth_reset', name: 'Reset' },
              ].map((fn) => (
                <button
                  key={fn.key}
                  onClick={() => setTargetFunction(fn.key)}
                  className={`px-2 py-0.5 rounded text-[11px] transition ${
                    targetFunction === fn.key
                      ? 'bg-slate-700 text-white font-semibold border border-slate-600'
                      : 'bg-slate-950 text-slate-400 hover:text-white border border-slate-800'
                  }`}
                >
                  {fn.name}
                </button>
              ))}
            </div>
          </div>

          <div className="flex items-center space-x-2 text-[11px] text-slate-400 flex-wrap">
            <span className="px-2 py-0.5 rounded bg-emerald-950/40 border border-emerald-800/60 text-emerald-400 font-medium">
              Auto-Alerts: Active
            </span>
            <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800">
              Session: <strong className="text-slate-200">{demoSessionId}</strong>
            </span>
            <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800">
              IP: <strong className="text-slate-200">198.51.100.99</strong>
            </span>
          </div>
        </div>

        {/* 6 Simulation Action Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 font-mono">
          {/* Action 1: Normal Access */}
          <button
            onClick={handleNormalAccess}
            disabled={activeAction !== null}
            className="p-2.5 rounded bg-slate-950/70 hover:bg-slate-800/80 border border-slate-800 hover:border-slate-700 text-left transition disabled:opacity-50 space-y-1 flex flex-col justify-between"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                <CheckCircle className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                Normal Access
              </span>
            </div>
            <p className="text-[10px] text-slate-500 leading-tight">
              Authorized request; score remains baseline.
            </p>
          </button>

          {/* Action 2: Repeated Access */}
          <button
            onClick={handleRepeatedAccess}
            disabled={activeAction !== null}
            className="p-2.5 rounded bg-slate-950/70 hover:bg-slate-800/80 border border-slate-800 hover:border-slate-700 text-left transition disabled:opacity-50 space-y-1 flex flex-col justify-between"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                <Repeat className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                Repeated Access
              </span>
            </div>
            <p className="text-[10px] text-slate-500 leading-tight">
              Burst frequency; applies attempt bonus.
            </p>
          </button>

          {/* Action 3: Sensitive Probe */}
          <button
            onClick={handleSensitiveProbe}
            disabled={activeAction !== null}
            className="p-2.5 rounded bg-slate-950/70 hover:bg-slate-800/80 border border-slate-800 hover:border-slate-700 text-left transition disabled:opacity-50 space-y-1 flex flex-col justify-between"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                Sensitive Probe
              </span>
            </div>
            <p className="text-[10px] text-slate-500 leading-tight">
              Probes secrets / .env; raises high base risk.
            </p>
          </button>

          {/* Action 4: Multi-Function Recon */}
          <button
            onClick={handleMultiRecon}
            disabled={activeAction !== null || isSimRunning}
            className="p-2.5 rounded bg-slate-950/70 hover:bg-slate-800/80 border border-slate-800 hover:border-slate-700 text-left transition disabled:opacity-50 space-y-1 flex flex-col justify-between"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                <Zap className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                Multi Recon
              </span>
            </div>
            <p className="text-[10px] text-slate-500 leading-tight">
              Cross-vector sequence; triggers synergies.
            </p>
          </button>

          {/* Action 5: Stop Simulation */}
          <button
            onClick={handleStopSimulation}
            disabled={activeAction === 'stop'}
            className="p-2.5 rounded bg-slate-950/70 hover:bg-slate-800/80 border border-slate-800 hover:border-slate-700 text-left transition disabled:opacity-50 space-y-1 flex flex-col justify-between"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                <Square className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                Stop Sim
              </span>
            </div>
            <p className="text-[10px] text-slate-500 leading-tight">
              Halts active reconnaissance immediately.
            </p>
          </button>

          {/* Action 6: Reset Demo */}
          <button
            onClick={handleResetDemoSession}
            disabled={activeAction === 'reset'}
            className="p-2.5 rounded bg-slate-950/70 hover:bg-slate-800/80 border border-slate-800 hover:border-slate-700 text-left transition disabled:opacity-50 space-y-1 flex flex-col justify-between"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                <RotateCcw className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                Reset Demo
              </span>
            </div>
            <p className="text-[10px] text-slate-500 leading-tight">
              Clears session telemetry; resets baseline.
            </p>
          </button>
        </div>

        {/* Compact Result Feedback */}
        {lastResult && (
          <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-xs font-mono flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center space-x-2">
              <span className="text-slate-400">Result:</span>
              <span className="font-bold text-slate-200 uppercase">{lastResult.action || lastResult.status}</span>
              {lastResult.function_name && (
                <span className="text-slate-400">
                  &bull; {lastResult.function_name}
                </span>
              )}
              {lastResult.attempts !== undefined && (
                <span className="text-slate-500">
                  (Attempts: {lastResult.attempts})
                </span>
              )}
            </div>

            {lastResult.function_risk_score !== undefined && (
              <div className="flex items-center space-x-2">
                <span className="text-slate-400">Risk Score:</span>
                {getRiskBandBadge(lastResult.function_risk_band, lastResult.function_risk_score)}
              </div>
            )}
          </div>
        )}
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* 3. FOUR COMPACT KPI CARDS                                         */}
      {/* ------------------------------------------------------------------ */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {/* KPI 1: Critical Functions */}
        <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>CRITICAL FUNCTIONS</span>
            <Layers className="h-3.5 w-3.5 text-slate-400" />
          </div>
          <div className="flex items-baseline justify-between pt-1 font-mono">
            <span className="text-2xl font-bold text-slate-100">{displayFunctions.length}</span>
            <span className="text-[10px] text-slate-500">Active Profiles</span>
          </div>
        </div>

        {/* KPI 2: Intercepted Attempts */}
        <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>INTERCEPTED ATTEMPTS</span>
            <Activity className="h-3.5 w-3.5 text-slate-400" />
          </div>
          <div className="flex items-baseline justify-between pt-1 font-mono">
            <span className="text-2xl font-bold text-slate-100">{totalEvents}</span>
            <span className="text-[10px] text-slate-500">
              Obs: {observedEvents} | Sim: {simulatedEvents}
            </span>
          </div>
        </div>

        {/* KPI 3: Multi-Function Threats */}
        <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>MULTI-FUNCTION THREATS</span>
            <ShieldAlert className="h-3.5 w-3.5 text-amber-400" />
          </div>
          <div className="flex items-baseline justify-between pt-1 font-mono">
            <span className="text-2xl font-bold text-amber-300">{multiFunctionThreatsCount}</span>
            <span className="text-[10px] text-slate-500">&ge;2 Functions Targeted</span>
          </div>
        </div>

        {/* KPI 4: Average Risk Score */}
        <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>AVERAGE RISK SCORE</span>
            <Crosshair className="h-3.5 w-3.5 text-slate-400" />
          </div>
          <div className="flex items-baseline justify-between pt-1 font-mono">
            <span className="text-2xl font-bold text-slate-100">{averageRiskScore}</span>
            <span className="text-[10px] text-slate-500">Bounded [0-100]</span>
          </div>
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* 4. SENSITIVE TARGET FUNCTIONS GRID                                */}
      {/* ------------------------------------------------------------------ */}
      <div className="rounded-lg bg-slate-900/60 border border-slate-800 p-3.5 space-y-3">
        {/* Section Header & Compact Filters */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-2.5">
          <div className="flex items-center space-x-2">
            <Layers className="h-4 w-4 text-slate-400" />
            <span className="font-mono text-xs font-semibold text-slate-200 uppercase tracking-wider">
              Sensitive Target Functions ({filteredFunctions.length})
            </span>
          </div>

          {/* Horizontally scrollable category filter pills */}
          <div className="flex items-center space-x-1 overflow-x-auto pb-0.5 text-xs font-mono scrollbar-none">
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => {
                  setSelectedCategory(cat);
                  setSelectedFuncFilter('all');
                }}
                className={`px-2 py-0.5 rounded text-[11px] whitespace-nowrap transition ${
                  selectedCategory === cat
                    ? 'bg-slate-700 text-white font-medium border border-slate-600'
                    : 'bg-slate-950 text-slate-400 hover:text-white border border-slate-800'
                }`}
              >
                {cat === 'all' ? 'All Categories' : cat}
              </button>
            ))}
          </div>
        </div>

        {/* Uniform 3/4 Column Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
          {filteredFunctions.map((fn) => {
            const Icon = getFunctionIcon(fn.key);
            const isSelected = selectedFuncFilter === fn.key;

            return (
              <div
                key={fn.key}
                onClick={() => setSelectedFuncFilter(isSelected ? 'all' : fn.key)}
                className={`p-3 rounded-lg bg-slate-950/60 border transition cursor-pointer space-y-2.5 ${
                  isSelected
                    ? 'border-slate-500 ring-1 ring-slate-500/60 bg-slate-900/80'
                    : 'border-slate-800/80 hover:border-slate-700'
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center space-x-2 min-w-0">
                    <div className="p-1.5 rounded bg-slate-900 border border-slate-800 text-slate-300 shrink-0">
                      <Icon className="w-4 h-4 text-cyan-400" />
                    </div>
                    <div className="min-w-0">
                      <h4 className="text-xs font-bold font-mono text-slate-100 truncate">
                        {fn.name}
                      </h4>
                      <span className="text-[10px] font-mono text-slate-500">
                        {fn.category}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center justify-between text-xs font-mono pt-1 border-t border-slate-800/60">
                  <span className="text-slate-400">
                    Weight: <strong className="text-slate-200">{fn.weight || 40}</strong>
                  </span>
                  <span className="text-slate-400">
                    Attempts: <strong className={fn.attempts > 0 ? 'text-amber-400' : 'text-slate-500'}>{fn.attempts || 0}</strong>
                  </span>
                </div>

                {/* Simple Horizontal Risk/Attempt Indicator */}
                <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-300 ${
                      fn.attempts > 0 ? 'bg-amber-400' : 'bg-slate-700'
                    }`}
                    style={{ width: `${Math.min(100, Math.max(8, (fn.attempts || 0) * 16))}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* 5. TWO-COLUMN LAYOUT: ATTACKER INTEL & INTERCEPTION FEED          */}
      {/* ------------------------------------------------------------------ */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* LEFT COLUMN: Top Function-Level Attackers */}
        <div className="rounded-lg bg-slate-900/60 border border-slate-800 p-4 space-y-3 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
              <div className="flex items-center space-x-2">
                <ShieldAlert className="h-4 w-4 text-slate-400" />
                <span className="font-mono text-xs font-semibold text-slate-200 uppercase tracking-wider">
                  Top Function-Level Attackers ({topAttackers.length})
                </span>
              </div>
              <span className="text-[11px] font-mono text-slate-500">
                Risk Range [0 - 100]
              </span>
            </div>

            {/* Attackers List */}
            <div className="space-y-2 max-h-[440px] overflow-y-auto pr-1">
              {topAttackers.length > 0 ? (
                topAttackers.map((atk) => {
                  const isExpanded = expandedAttackerId === atk.id;

                  return (
                    <div
                      key={atk.id}
                      className="p-3 rounded bg-slate-950/50 border border-slate-800/80 hover:border-slate-700 transition font-mono text-xs space-y-2"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <span className="font-bold text-slate-100">{atk.ip}</span>
                          {atk.is_simulated && (
                            <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">
                              SIM
                            </span>
                          )}
                          <button
                            onClick={() => setSelectedAttackerId(atk.id)}
                            className="text-slate-400 hover:text-white"
                            title="Inspect Attacker Dossier"
                          >
                            <ExternalLink className="w-3.5 h-3.5" />
                          </button>
                        </div>

                        <div>
                          {getRiskBandBadge(atk.risk_band, atk.function_risk_score)}
                        </div>
                      </div>

                      {/* Targeted functions pills */}
                      <div className="flex items-center space-x-1.5 flex-wrap gap-y-1 text-[11px]">
                        <span className="text-slate-500">Targeted:</span>
                        {(atk.targeted_functions || []).map((fn, idx) => (
                          <span
                            key={idx}
                            className="px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800 text-slate-300 text-[10px]"
                          >
                            {fn}
                          </span>
                        ))}
                      </div>

                      {/* Short Threat Summary & Expand Toggle */}
                      <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-slate-800/60">
                        <span className="truncate max-w-[260px]">
                          {atk.explanation ? atk.explanation.slice(0, 50) + '...' : 'Reconnaissance pattern detected'}
                        </span>
                        <button
                          onClick={() => setExpandedAttackerId(isExpanded ? null : atk.id)}
                          className="text-slate-400 hover:text-white flex items-center gap-1 text-[11px]"
                        >
                          <span>{isExpanded ? 'Less' : 'Details'}</span>
                          {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                        </button>
                      </div>

                      {/* Expandable Detailed Information */}
                      {isExpanded && (
                        <div className="pt-2 border-t border-slate-800/60 space-y-2 text-[11px] text-slate-300">
                          {atk.explanation && (
                            <div className="p-2 rounded bg-slate-900/70 text-slate-300 leading-relaxed">
                              {atk.explanation}
                            </div>
                          )}

                          <div className="flex items-center justify-between pt-1">
                            <span className="text-slate-500">
                              Window: {atk.time_window_seconds ? `${atk.time_window_seconds}s` : 'Single event'}
                            </span>
                            <button
                              onClick={() => blockAttacker(atk.ip, 'Critical function attack synergy threshold exceeded')}
                              className="px-2.5 py-1 rounded bg-rose-950/60 hover:bg-rose-900/80 border border-rose-800 text-rose-300 text-[10px] font-semibold flex items-center gap-1 transition"
                            >
                              <Lock className="w-3 h-3" />
                              <span>Block IP</span>
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })
              ) : (
                <div className="py-12 text-center text-xs font-mono text-slate-500">
                  No high-risk function targeting recorded yet.
                </div>
              )}
            </div>
          </div>
        </div>

        {/* RIGHT COLUMN: Real-Time Function Interception Feed */}
        <div className="rounded-lg bg-slate-900/60 border border-slate-800 p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
            <div className="flex items-center space-x-2">
              <Activity className="h-4 w-4 text-slate-400" />
              <span className="font-mono text-xs font-semibold text-slate-200 uppercase tracking-wider">
                Real-Time Function Interception Feed
              </span>
            </div>

            {/* Source Filter: All / Observed / Simulated */}
            <div className="flex items-center space-x-1 text-xs font-mono">
              {['all', 'observed', 'simulated'].map((src) => (
                <button
                  key={src}
                  onClick={() => setSourceFilter(src)}
                  className={`px-2 py-0.5 rounded text-[10px] uppercase transition ${
                    sourceFilter === src
                      ? 'bg-slate-700 text-white font-semibold'
                      : 'bg-slate-950 text-slate-400 hover:text-white border border-slate-800'
                  }`}
                >
                  {src}
                </button>
              ))}
            </div>
          </div>

          {/* Interception Feed List */}
          <div className="space-y-2 max-h-[440px] overflow-y-auto pr-1">
            {filteredEvents.length > 0 ? (
              filteredEvents.slice(0, 30).map((ev, idx) => {
                const isCrit = ev?.severity === 'critical' || (ev?.function_risk_score && ev.function_risk_score >= 70);
                const isWarn = ev?.severity === 'high' || (ev?.function_risk_score && ev.function_risk_score >= 30);

                return (
                  <div
                    key={ev.id || idx}
                    className="p-2.5 rounded bg-slate-950/50 border border-slate-800/80 hover:border-slate-700 transition font-mono text-xs space-y-1.5"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center space-x-2 min-w-0">
                        <span
                          className={`h-2 w-2 rounded-full shrink-0 ${
                            isCrit ? 'bg-rose-500' : isWarn ? 'bg-amber-400' : 'bg-slate-500'
                          }`}
                        />
                        <span className="font-bold text-slate-200 truncate">{ev.src_ip}</span>
                        <span className="text-slate-500">&rarr;</span>
                        <span className="text-slate-300 font-medium truncate">{ev.target_function}</span>
                      </div>

                      <div className="flex items-center space-x-2 shrink-0 text-[10px]">
                        {ev.is_simulated ? (
                          <span className="px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 border border-slate-700">
                            SIM
                          </span>
                        ) : (
                          <span className="px-1.5 py-0.2 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800">
                            OBS
                          </span>
                        )}
                        <span className="text-slate-500">
                          {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : 'Recent'}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center justify-between text-[11px] text-slate-500 pt-0.5">
                      <span className="truncate">
                        Endpoint: <code className="text-slate-400">{ev.target_endpoint || `/${ev.target_function}`}</code>
                      </span>
                      {ev.session_id && (
                        <span className="text-[10px] text-slate-500 truncate max-w-[140px]">
                          sess: {ev.session_id}
                        </span>
                      )}
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="py-12 text-center text-xs font-mono text-slate-500">
                Awaiting real-time function targeting telemetry...
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
