import React, { useState, useEffect } from 'react';
import {
  Server,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Play,
  RotateCcw,
  CheckCircle,
  Clock,
  Activity,
  ArrowRight,
  RefreshCw,
  Sliders,
  Check,
  XCircle,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { api } from '../api/client';
import RemediationAdvisorCard from './RemediationAdvisorCard';

const STATUS_STEPS = ['operational', 'attacked', 'taken_down', 'fixing', 'restored'];

export default function GatewayLifecyclePanel() {
  const [gateways, setGateways] = useState([]);
  const [loading, setLoading] = useState(true);
  const [verifyingId, setVerifyingId] = useState(null);
  const [updatingId, setUpdatingId] = useState(null);
  const [expandedAdvisoryId, setExpandedAdvisoryId] = useState(null);
  const [now, setNow] = useState(Date.now());

  const fetchGateways = async () => {
    try {
      const res = await api.getGateways();
      if (res && res.gateways) {
        setGateways(res.gateways);
      }
    } catch (err) {
      console.error('Failed to load gateways:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGateways();
    const timer = setInterval(() => {
      setNow(Date.now());
    }, 1000);
    const poll = setInterval(fetchGateways, 4000);
    return () => {
      clearInterval(timer);
      clearInterval(poll);
    };
  }, []);

  const handleStatusChange = async (gatewayId, nextStatus) => {
    try {
      setUpdatingId(gatewayId);
      await api.updateGatewayStatus(gatewayId, nextStatus, `Operator transition to ${nextStatus}`);
      await fetchGateways();
    } catch (err) {
      alert(`Status transition failed: ${err.message}`);
    } finally {
      setUpdatingId(null);
    }
  };

  const handleVerifyFix = async (gatewayId, forceResult = null) => {
    try {
      setVerifyingId(gatewayId);
      const res = await api.verifyGatewayFix(gatewayId, {
        force_result: forceResult,
      });
      await fetchGateways();
    } catch (err) {
      alert(`Verification replay failed: ${err.message}`);
    } finally {
      setVerifyingId(null);
    }
  };

  const formatWatchRemaining = (watchUntilStr) => {
    if (!watchUntilStr) return null;
    const until = new Date(watchUntilStr).getTime();
    const diffSec = Math.max(0, Math.floor((until - now) / 1000));
    if (diffSec <= 0) return null;
    const mins = Math.floor(diffSec / 60);
    const secs = diffSec % 60;
    return `${mins}m ${secs < 10 ? '0' : ''}${secs}s`;
  };

  if (loading && gateways.length === 0) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 flex items-center justify-center space-x-3 text-slate-400">
        <RefreshCw className="w-5 h-5 animate-spin text-indigo-400" />
        <span className="text-sm font-mono">Loading Gateway Lifecycle Status...</span>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* HEADER */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-slate-900 border border-slate-800 rounded-xl p-4">
        <div>
          <div className="flex items-center space-x-2">
            <Server className="w-5 h-5 text-indigo-400" />
            <h2 className="text-base font-bold text-white tracking-wide uppercase">
              Gateway Lifecycle & Hardening Management
            </h2>
            <span className="text-[10px] px-2 py-0.5 rounded bg-indigo-500/10 border border-indigo-500/30 text-indigo-300 font-bold uppercase">
              Proven-Fix Loop
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Tracks gateways across Attacked &rarr; Taken down &rarr; Fixing &rarr; Restored &rarr; Watch Mode.
          </p>
        </div>

        <button
          onClick={fetchGateways}
          className="flex items-center space-x-1 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 rounded text-xs font-semibold self-start md:self-auto transition-all"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Gateways</span>
        </button>
      </div>

      {/* 3 GATEWAY CARDS */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {gateways.map((gw) => {
          const watchTimer = formatWatchRemaining(gw.watch_until);
          const isWatch = gw.is_watch_mode || Boolean(watchTimer);
          const isExpanded = expandedAdvisoryId === gw.id;

          // Stepper index
          const stepIndex = STATUS_STEPS.indexOf(gw.status);

          return (
            <div
              key={gw.id}
              className={`bg-slate-900/90 border rounded-xl overflow-hidden flex flex-col justify-between transition-all ${
                gw.reattack_after_restore
                  ? 'border-red-500/50 shadow-lg shadow-red-950/20'
                  : isWatch
                  ? 'border-cyan-500/40 shadow-lg shadow-cyan-950/20'
                  : 'border-slate-800 hover:border-slate-700'
              }`}
            >
              {/* CARD TOP */}
              <div className="p-4 space-y-3">
                {/* RE-ATTACK BANNER */}
                {gw.reattack_after_restore && (
                  <div className="p-2 bg-red-950/80 border border-red-500/60 rounded text-red-200 text-xs font-bold flex items-center space-x-1.5 animate-pulse">
                    <ShieldAlert className="w-4 h-4 text-red-400 flex-shrink-0" />
                    <span>Re-attacked after restore ({gw.reattack_count} times)</span>
                  </div>
                )}

                {/* WATCH MODE BANNER */}
                {isWatch && (
                  <div className="p-2 bg-cyan-950/70 border border-cyan-500/50 rounded text-cyan-200 text-xs font-bold flex items-center justify-between">
                    <div className="flex items-center space-x-1.5">
                      <Clock className="w-4 h-4 text-cyan-400 flex-shrink-0 animate-spin" />
                      <span>WATCH MODE ACTIVE (-20% threshold)</span>
                    </div>
                    {watchTimer && (
                      <span className="font-mono text-cyan-300 font-extrabold">{watchTimer}</span>
                    )}
                  </div>
                )}

                {/* GATEWAY IDENTITY */}
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-white flex items-center space-x-2">
                      <span>{gw.name}</span>
                    </h3>
                    <div className="flex items-center space-x-2 text-[11px] font-mono text-slate-400 mt-0.5">
                      <span>{gw.endpoint_prefix}</span>
                      <span>&bull;</span>
                      <span className="text-slate-500">{gw.owner_team}</span>
                    </div>
                  </div>

                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-extrabold uppercase tracking-wider border ${
                      gw.status === 'attacked'
                        ? 'bg-red-500/10 border-red-500/40 text-red-400 animate-pulse'
                        : gw.status === 'taken_down'
                        ? 'bg-amber-500/10 border-amber-500/40 text-amber-400'
                        : gw.status === 'fixing'
                        ? 'bg-blue-500/10 border-blue-500/40 text-blue-400'
                        : gw.status === 'restored'
                        ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-400'
                        : 'bg-slate-800 border-slate-700 text-slate-300'
                    }`}
                  >
                    {gw.status.replace('_', ' ')}
                  </span>
                </div>

                {/* STATUS STEPPER */}
                <div className="space-y-1.5 pt-1">
                  <div className="text-[10px] uppercase font-bold tracking-wider text-slate-500">
                    Lifecycle Stepper
                  </div>
                  <div className="grid grid-cols-4 gap-1">
                    {['attacked', 'taken_down', 'fixing', 'restored'].map((st, i) => {
                      const isCurrent = gw.status === st;
                      const isPast = stepIndex > STATUS_STEPS.indexOf(st);
                      return (
                        <button
                          key={st}
                          onClick={() => handleStatusChange(gw.id, st)}
                          disabled={updatingId === gw.id}
                          className={`py-1 px-1 rounded text-[10px] font-bold text-center border transition-all ${
                            isCurrent
                              ? 'bg-indigo-600 border-indigo-400 text-white shadow-md'
                              : isPast
                              ? 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700'
                              : 'bg-slate-950 border-slate-800 text-slate-500 hover:border-slate-700'
                          }`}
                        >
                          {st === 'taken_down' ? 'Down' : st.replace('_', ' ').slice(0, 7)}
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* SAFE TO REOPEN INDICATOR */}
                <div className="pt-2 border-t border-slate-800/80">
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="text-slate-400 font-medium">Safe to Reopen:</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border flex items-center space-x-1 ${
                        gw.safe_to_reopen
                          ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-300'
                          : 'bg-amber-500/10 border-amber-500/40 text-amber-300'
                      }`}
                    >
                      {gw.safe_to_reopen ? (
                        <>
                          <CheckCircle className="w-3 h-3 text-emerald-400" />
                          <span>SAFE TO REOPEN</span>
                        </>
                      ) : (
                        <>
                          <AlertTriangle className="w-3 h-3 text-amber-400" />
                          <span>HOLD (AMBER)</span>
                        </>
                      )}
                    </span>
                  </div>
                  {!gw.safe_to_reopen && gw.safe_to_reopen_reasons && gw.safe_to_reopen_reasons.length > 0 && (
                    <p className="text-[10px] text-amber-400/80 leading-tight">
                      &bull; {gw.safe_to_reopen_reasons[0]}
                    </p>
                  )}
                </div>

                {/* VERIFICATION RESULT DETAILS */}
                {gw.last_verify_result && (
                  <div className="p-2 bg-slate-950/60 border border-slate-800 rounded text-xs space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] text-slate-500 font-bold uppercase">Replay Test:</span>
                      <span
                        className={`font-mono text-[10px] font-bold ${
                          gw.last_verify_result.status === 'passed' ? 'text-emerald-400' : 'text-red-400'
                        }`}
                      >
                        {gw.last_verify_result.summary || gw.last_verify_result.status.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-[10px] text-slate-400 truncate">
                      {gw.last_verify_result.details}
                    </p>
                  </div>
                )}
              </div>

              {/* CARD BOTTOM ACTION BUTTONS */}
              <div className="p-3 bg-slate-950/60 border-t border-slate-800 flex items-center justify-between gap-2">
                <button
                  onClick={() => handleVerifyFix(gw.id)}
                  disabled={verifyingId === gw.id}
                  className="flex-1 py-1.5 px-2 bg-indigo-950 hover:bg-indigo-900 border border-indigo-500/40 text-indigo-200 rounded text-xs font-bold flex items-center justify-center space-x-1.5 transition-all disabled:opacity-50"
                >
                  <ShieldCheck className={`w-3.5 h-3.5 ${verifyingId === gw.id ? 'animate-spin' : ''}`} />
                  <span>{verifyingId === gw.id ? 'Replaying...' : 'Verify Fix'}</span>
                </button>

                <button
                  onClick={() => setExpandedAdvisoryId(isExpanded ? null : gw.id)}
                  className="py-1.5 px-2.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 rounded text-xs font-semibold flex items-center space-x-1 transition-all"
                  title="View tailored Remediation Advisory"
                >
                  <span>Advisory</span>
                  {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                </button>
              </div>

              {/* EXPANDED ADVISORY DRAWER */}
              {isExpanded && (
                <div className="p-3 bg-slate-950 border-t border-slate-800">
                  <RemediationAdvisorCard gatewayId={gw.id} />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

