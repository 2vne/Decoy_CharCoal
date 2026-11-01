import React, { useState, useEffect } from 'react';
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
  Square,
  Repeat,
  Radio,
  Wifi,
  WifiOff,
  Crosshair,
  Server,
} from 'lucide-react';
import { useSoc } from '../context/SocContext';
import { api } from '../api/client';

export default function FunctionIntelligencePage() {
  const {
    functionStats,
    functionEvents,
    refreshFunctionStats,
    refreshPagerdutyData,
    refreshAllData,
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

  // Filters
  const [selectedFuncFilter, setSelectedFuncFilter] = useState('all');
  const [sourceFilter, setSourceFilter] = useState('all'); // all, observed, simulated

  const metadata = functionStats?.metadata || {};
  const mostTargeted = functionStats?.most_targeted_functions || [];
  const topAttackers = functionStats?.top_attackers || [];
  const totalEvents = functionStats?.total_targeted_events || 0;
  const observedEvents = functionStats?.observed_events_count || 0;
  const simulatedEvents = functionStats?.simulated_events_count || 0;

  // Poll demo status on mount or when sim is running
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
          // ignore polling failure
        }
      }, 1500);
    }
    return () => clearInterval(timer);
  }, [isSimRunning, demoSessionId]);

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

  // --------------------------------------------------------------------------
  // Manual Demonstration Action Handlers
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
      addToast(`Normal Function Access: ${res.function_name} evaluated (Score: ${res.function_risk_score.toFixed(1)})`, 'info');
      await refreshFunctionStats();
    } catch (err) {
      console.error(err);
      setActionError(err.message || 'Failed to trigger Normal Function Access');
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
      addToast(`Repeated Function Access: ${res.function_name} (Attempts: ${res.attempts}) -> PAGERDUTY CALL DISPATCHED`, 'error'); if (refreshPagerdutyData) refreshPagerdutyData();
      await refreshFunctionStats();
    } catch (err) {
      console.error(err);
      setActionError(err.message || 'Failed to trigger Repeated Function Access');
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
      addToast(`Sensitive Function Probed: ${res.function_name} -> CRITICAL PAGERDUTY CALL DISPATCHED`, 'error'); if (refreshPagerdutyData) refreshPagerdutyData();
      await refreshFunctionStats();
    } catch (err) {
      console.error(err);
      setActionError(err.message || 'Failed to trigger Sensitive Function Probing');
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
      addToast('Multi-Function Reconnaissance sequence streaming live via WebSocket...', 'warning');
      // refresh stats after brief cadence
      setTimeout(() => { refreshFunctionStats(); if (refreshPagerdutyData) refreshPagerdutyData(); }, 1200);
      setTimeout(() => refreshFunctionStats(), 2200);
    } catch (err) {
      console.error(err);
      setActionError(err.message || 'Failed to trigger Multi-Function Reconnaissance');
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
      addToast('Simulation halted immediately.', 'info');
      await refreshFunctionStats();
    } catch (err) {
      console.error(err);
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
      addToast('Isolated demo session reset: baseline 0 restored.', 'info');
      await refreshFunctionStats();
    } catch (err) {
      console.error(err);
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
                Beyond generic MITRE signatures: Identifying targeted critical system functions,
                detecting attack synergies, and computing bounded explainable risk scores [0 - 100].
              </p>
            </div>
          </div>
        </div>

        {/* Global Connection & Refresh Status */}
        <div className="flex items-center space-x-3">
          <div
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-full border text-xs font-mono ${
              isLiveConnected
                ? 'bg-emerald-950/80 border-emerald-500/40 text-emerald-400'
                : 'bg-red-950/80 border-red-500/40 text-red-400'
            }`}
          >
            {isLiveConnected ? (
              <>
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
                <Wifi className="w-3.5 h-3.5 ml-1" />
                <span>LIVE TELEMETRY</span>
              </>
            ) : (
              <>
                <WifiOff className="w-3.5 h-3.5" />
                <span>WS OFFLINE</span>
              </>
            )}
          </div>
          <button
            onClick={refreshFunctionStats}
            className="p-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 rounded text-xs font-mono transition-all flex items-center gap-1.5"
            title="Refresh Intelligence"
          >
            <RotateCcw className="w-4 h-4" />
            <span className="hidden sm:inline">Refresh</span>
          </button>
        </div>
      </div>

      {/* Connection / API Error Alert */}
      {(!isLiveConnected || actionError || backendError) && (
        <div className="bg-red-950/40 border border-red-500/50 rounded-lg p-3 text-xs font-mono text-red-300 flex items-start justify-between">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />
            <div>
              <span className="font-bold">SYSTEM NOTICE: </span>
              {actionError
                ? actionError
                : !isLiveConnected
                ? 'WebSocket connection offline. Backend events are being recorded in SQLite and will populate upon reconnection.'
                : backendError}
            </div>
          </div>
          {actionError && (
            <button
              onClick={() => setActionError(null)}
              className="text-red-400 hover:text-white underline ml-3 flex-shrink-0"
            >
              Dismiss
            </button>
          )}
        </div>
      )}

      {/* ---------------------------------------------------------------------- */}
      {/* MANUAL DEMONSTRATION CONTROLS (HACKATHON PRESENTATION PANEL)          */}
      {/* ---------------------------------------------------------------------- */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900 to-slate-950 border-2 border-indigo-500/40 rounded-xl p-5 shadow-2xl space-y-4">
        {/* Panel Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between pb-3 border-b border-slate-800 gap-3">
          <div className="flex items-center space-x-2.5">
            <div className="p-1.5 bg-indigo-950 border border-indigo-500/50 rounded text-indigo-400">
              <Crosshair className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <h2 className="text-sm font-bold font-mono text-white tracking-wider flex items-center gap-2">
                MANUAL FUNCTION INTELLIGENCE DEMONSTRATION CONTROLS
                <span className="text-[10px] px-2 py-0.5 rounded bg-indigo-950 border border-indigo-500/40 text-indigo-300 font-normal">
                  HACKATHON CONTROLS
                </span>
              </h2>
              <p className="text-[11px] font-mono text-slate-400">
                Trigger controlled synthetic actions directly into the backend telemetry pipeline without external scripts.
              </p>
            </div>
          </div>

          {/* Session & Target Metadata */}
          <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
            <div className="px-2.5 py-1 bg-emerald-950/80 border border-emerald-500/50 rounded text-emerald-300 flex items-center gap-1.5 shadow-[0_0_8px_rgba(16,185,129,0.2)]" title="Autonomous attack alert dispatch is active">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              <span className="font-bold text-[10px] tracking-wide">AUTO-ALERTS: ACTIVE</span>
            </div>
            <div className="px-2.5 py-1 bg-slate-950 border border-slate-800 rounded text-slate-300 flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-blue-400" />
              <span>Session:</span>
              <span className="text-indigo-400 font-bold">{demoSessionId}</span>
            </div>
            <div className="px-2.5 py-1 bg-slate-950 border border-slate-800 rounded text-slate-300 flex items-center gap-1.5">
              <span>Target IP:</span>
              <span className="text-purple-400 font-bold">198.51.100.99</span>
            </div>
          </div>
        </div>

        {/* Function Target Selector */}
        <div className="flex flex-wrap items-center gap-2 pt-1 font-mono text-xs">
          <span className="text-slate-400 font-bold flex items-center gap-1">
            <Layers className="w-3.5 h-3.5 text-blue-400" />
            Selected Function Target:
          </span>
          {[
            { key: 'auth_login', name: 'Login / Auth' },
            { key: 'auth_otp', name: 'OTP / 2FA' },
            { key: 'admin_access', name: 'Admin Console' },
            { key: 'payment_gateway', name: 'Payment API' },
            { key: 'database_api', name: 'Database Core' },
            { key: 'secrets_env', name: 'Secrets / .env' },
            { key: 'auth_reset', name: 'Password Reset' },
          ].map((fn) => (
            <button
              key={fn.key}
              onClick={() => setTargetFunction(fn.key)}
              className={`px-2.5 py-1 rounded text-xs transition-all ${
                targetFunction === fn.key
                  ? 'bg-indigo-600 text-white font-bold shadow-md shadow-indigo-600/30 ring-1 ring-indigo-400'
                  : 'bg-slate-800/80 text-slate-300 hover:bg-slate-700 hover:text-white border border-slate-700/60'
              }`}
            >
              {fn.name}
            </button>
          ))}
        </div>

        {/* 6 Working Control Buttons Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-3 pt-2">
          {/* 1. Normal Function Access */}
          <button
            onClick={handleNormalAccess}
            disabled={activeAction !== null}
            className="flex flex-col items-start p-3 bg-slate-950/80 hover:bg-slate-800/90 border border-emerald-500/40 hover:border-emerald-500 text-left rounded-lg transition-all group disabled:opacity-50"
          >
            <div className="flex items-center justify-between w-full mb-1.5">
              <span className="text-xs font-bold font-mono text-emerald-400 flex items-center gap-1">
                <CheckCircle className="w-3.5 h-3.5" />
                1. Normal Access
              </span>
              <span className="text-[10px] font-mono px-1 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-500/30">
                Att: 1
              </span>
            </div>
            <div className="text-[11px] font-mono text-slate-300 font-semibold">
              {activeAction === 'normal' ? 'Executing...' : 'Legitimate Request'}
            </div>
            <p className="text-[10px] font-mono text-slate-500 mt-1 line-clamp-2">
              Single authorized request to {targetFunction}. Score remains low [0 - 15].
            </p>
          </button>

          {/* 2. Repeated Function Access */}
          <button
            onClick={handleRepeatedAccess}
            disabled={activeAction !== null}
            className="flex flex-col items-start p-3 bg-slate-950/80 hover:bg-slate-800/90 border border-amber-500/40 hover:border-amber-500 text-left rounded-lg transition-all group disabled:opacity-50"
          >
            <div className="flex items-center justify-between w-full mb-1.5">
              <span className="text-xs font-bold font-mono text-amber-400 flex items-center gap-1">
                <Repeat className="w-3.5 h-3.5" />
                2. Repeated Access
              </span>
              <span className="text-[10px] font-mono px-1 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-500/30">
                Burst +2
              </span>
            </div>
            <div className="text-[11px] font-mono text-slate-300 font-semibold">
              {activeAction === 'repeated' ? 'Bursting...' : 'Escalate Frequency'}
            </div>
            <p className="text-[10px] font-mono text-slate-500 mt-1 line-clamp-2">
              Increments attempt count on same function. Demonstrates logarithmic attempt bonus.
            </p>
          </button>

          {/* 3. Sensitive Function Probing */}
          <button
            onClick={handleSensitiveProbe}
            disabled={activeAction !== null}
            className="flex flex-col items-start p-3 bg-slate-950/80 hover:bg-slate-800/90 border border-red-500/40 hover:border-red-500 text-left rounded-lg transition-all group disabled:opacity-50"
          >
            <div className="flex items-center justify-between w-full mb-1.5">
              <span className="text-xs font-bold font-mono text-red-400 flex items-center gap-1">
                <ShieldAlert className="w-3.5 h-3.5" />
                3. Sensitive Probe
              </span>
              <span className="text-[10px] font-mono px-1 py-0.5 rounded bg-red-950 text-red-300 border border-red-500/30">
                Critical Trap
              </span>
            </div>
            <div className="text-[11px] font-mono text-slate-300 font-semibold">
              {activeAction === 'sensitive' ? 'Probing...' : 'Probe Secrets / Admin'}
            </div>
            <p className="text-[10px] font-mono text-slate-500 mt-1 line-clamp-2">
              Unauthorized probe for .env / secrets. Triggers immediate high base impact.
            </p>
          </button>

          {/* 4. Multi-Function Reconnaissance */}
          <button
            onClick={handleMultiRecon}
            disabled={activeAction !== null || isSimRunning}
            className="flex flex-col items-start p-3 bg-slate-950/80 hover:bg-slate-800/90 border border-purple-500/40 hover:border-purple-500 text-left rounded-lg transition-all group disabled:opacity-50"
          >
            <div className="flex items-center justify-between w-full mb-1.5">
              <span className="text-xs font-bold font-mono text-purple-400 flex items-center gap-1">
                <Zap className="w-3.5 h-3.5" />
                4. Multi Recon
              </span>
              <span className="text-[10px] font-mono px-1 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-500/30">
                4 Functions
              </span>
            </div>
            <div className="text-[11px] font-mono text-slate-300 font-semibold">
              {isSimRunning ? 'Streaming Sequence...' : 'Synergy Burst (4x)'}
            </div>
            <p className="text-[10px] font-mono text-slate-500 mt-1 line-clamp-2">
              Targets Login &rarr; OTP &rarr; Admin &rarr; Database. Triggers multi-vector synergies.
            </p>
          </button>

          {/* 5. Stop Simulation */}
          <button
            onClick={handleStopSimulation}
            disabled={activeAction === 'stop'}
            className="flex flex-col items-start p-3 bg-slate-950/80 hover:bg-slate-800/90 border border-orange-500/40 hover:border-orange-500 text-left rounded-lg transition-all group disabled:opacity-50"
          >
            <div className="flex items-center justify-between w-full mb-1.5">
              <span className="text-xs font-bold font-mono text-orange-400 flex items-center gap-1">
                <Square className="w-3.5 h-3.5" />
                5. Stop Sim
              </span>
              <span className="text-[10px] font-mono px-1 py-0.5 rounded bg-orange-950 text-orange-300 border border-orange-500/30">
                Halt
              </span>
            </div>
            <div className="text-[11px] font-mono text-slate-300 font-semibold">
              {activeAction === 'stop' ? 'Stopping...' : 'Immediate Abort'}
            </div>
            <p className="text-[10px] font-mono text-slate-500 mt-1 line-clamp-2">
              Cancels active reconnaissance generator. Stops backend dispatch immediately.
            </p>
          </button>

          {/* 6. Reset Isolated Demo Session */}
          <button
            onClick={handleResetDemoSession}
            disabled={activeAction === 'reset'}
            className="flex flex-col items-start p-3 bg-slate-950/80 hover:bg-slate-800/90 border border-slate-600/50 hover:border-red-400 text-left rounded-lg transition-all group disabled:opacity-50"
          >
            <div className="flex items-center justify-between w-full mb-1.5">
              <span className="text-xs font-bold font-mono text-slate-300 group-hover:text-red-400 flex items-center gap-1">
                <RotateCcw className="w-3.5 h-3.5" />
                6. Reset Demo
              </span>
              <span className="text-[10px] font-mono px-1 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                Purge
              </span>
            </div>
            <div className="text-[11px] font-mono text-slate-300 font-semibold">
              {activeAction === 'reset' ? 'Resetting...' : 'Reset Session'}
            </div>
            <p className="text-[10px] font-mono text-slate-500 mt-1 line-clamp-2">
              Clears isolated demo telemetry. Restores 0 baseline. Genuine data preserved.
            </p>
          </button>
        </div>

        {/* Live Feedback & Explanatory Output Banner */}
        {lastResult && (
          <div className="bg-slate-950 border border-indigo-500/30 rounded-lg p-3 text-xs font-mono space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-2">
              <div className="flex items-center space-x-2">
                <span className="text-slate-400">Action Result:</span>
                <span className="text-emerald-400 font-bold uppercase">{lastResult.action || lastResult.status}</span>
                {lastResult.target_function && (
                  <span className="text-white bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
                    Target: {lastResult.function_name || lastResult.target_function} ({lastResult.category || 'General'})
                  </span>
                )}
                {lastResult.attempts !== undefined && (
                  <span className="text-amber-400 bg-amber-950/60 px-2 py-0.5 rounded border border-amber-500/30">
                    Attempts: {lastResult.attempts}
                  </span>
                )}
              </div>
              {lastResult.function_risk_score !== undefined && (
                <div className="flex items-center space-x-2">
                  <span className="text-slate-400">Level-2 Function Risk:</span>
                  {getRiskBandBadge(lastResult.function_risk_band, lastResult.function_risk_score)}
                </div>
              )}
            </div>

            {lastResult.explanation && (
              <div className="text-slate-300 text-[11px] bg-indigo-950/30 p-2 rounded border border-indigo-500/20">
                <span className="text-indigo-400 font-bold">Mathematical Breakdown: </span>
                {lastResult.explanation}
              </div>
            )}
            {lastResult.message && (
              <div className="text-slate-400 text-[11px] italic">
                {lastResult.message}
              </div>
            )}
          </div>
        )}
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
                No high-risk function targeting recorded yet. Use the demonstration controls above to test live calculation.
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
                  key={ev.id || `${ev.src_ip}-${ev.timestamp}-${Math.random()}`}
                  className="bg-slate-950/60 border border-slate-800/80 rounded p-3 font-mono text-xs hover:border-slate-700 transition-all"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <span className="font-bold text-slate-200">{ev.src_ip}</span>
                      <span className="text-slate-500">&rarr;</span>
                      <span className="text-amber-400 font-bold">{ev.target_function}</span>
                      {ev.category && (
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">
                          {ev.category}
                        </span>
                      )}
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

                  <div className="mt-1 text-slate-400 text-[11px] truncate flex items-center justify-between">
                    <span>
                      Endpoint: <span className="text-slate-300">{ev.target_endpoint || `/${ev.target_function}`}</span>
                    </span>
                    {ev.session_id && (
                      <span className="text-[10px] text-indigo-400">
                        sess: {ev.session_id}
                      </span>
                    )}
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
