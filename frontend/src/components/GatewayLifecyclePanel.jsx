import React, { useState, useEffect } from 'react';
import {
  Server,
  ShieldAlert,
  CheckCircle,
  Clock,
  RefreshCw,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  ShieldCheck,
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
      await api.verifyGatewayFix(gatewayId, {
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
      <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-6 flex items-center justify-center space-x-2 text-slate-400 font-mono text-xs">
        <RefreshCw className="w-4 h-4 animate-spin text-slate-300" />
        <span>Loading Gateway Lifecycle Status...</span>
      </div>
    );
  }

  return (
    <div className="rounded-lg bg-slate-900/60 border border-slate-800 p-3.5 space-y-3 font-sans">
      {/* COMPACT SECTION HEADER */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-2.5">
        <div className="flex items-center space-x-2">
          <Server className="w-4 h-4 text-slate-400" />
          <h2 className="text-xs font-semibold font-mono text-slate-200 uppercase tracking-wider">
            Gateway Lifecycle & Hardening
          </h2>
          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 border border-slate-700">
            {gateways.length} Gateways
          </span>
        </div>

        <button
          onClick={fetchGateways}
          className="flex items-center space-x-1 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-white rounded text-xs font-mono transition self-start sm:self-auto"
          title="Refresh lifecycle telemetry"
        >
          <RefreshCw className="w-3 h-3" />
          <span>Refresh</span>
        </button>
      </div>

      {/* 3 UNIFORM GATEWAY CARDS */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {gateways.map((gw) => {
          const watchTimer = formatWatchRemaining(gw.watch_until);
          const isWatch = gw.is_watch_mode || Boolean(watchTimer);
          const isExpanded = expandedAdvisoryId === gw.id;
          const stepIndex = STATUS_STEPS.indexOf(gw.status);

          return (
            <div
              key={gw.id}
              className={`rounded-lg bg-slate-950/70 border flex flex-col justify-between transition ${
                gw.reattack_after_restore
                  ? 'border-rose-800/80'
                  : isWatch
                  ? 'border-cyan-800/80'
                  : 'border-slate-800/80 hover:border-slate-700'
              }`}
            >
              <div className="p-3 space-y-2.5">
                {/* RE-ATTACK BANNER (Conditional) */}
                {gw.reattack_after_restore && (
                  <div className="p-1.5 bg-rose-950/60 border border-rose-800 rounded text-rose-300 text-[11px] font-mono font-medium flex items-center space-x-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                    <span>Re-attacked after restore ({gw.reattack_count}x)</span>
                  </div>
                )}

                {/* WATCH MODE BANNER (Conditional) */}
                {isWatch && (
                  <div className="p-1.5 bg-cyan-950/50 border border-cyan-800 rounded text-cyan-300 text-[11px] font-mono flex items-center justify-between">
                    <div className="flex items-center space-x-1.5">
                      <Clock className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                      <span>Watch Mode (-20% threshold)</span>
                    </div>
                    {watchTimer && (
                      <span className="font-bold text-cyan-200">{watchTimer}</span>
                    )}
                  </div>
                )}

                {/* GATEWAY IDENTITY */}
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <h3 className="text-xs font-bold font-mono text-slate-100 truncate">
                      {gw.name}
                    </h3>
                    <div className="text-[11px] font-mono text-slate-500 truncate mt-0.5">
                      <code>{gw.endpoint_prefix}</code> &bull; {gw.owner_team}
                    </div>
                  </div>

                  <span
                    className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-semibold uppercase tracking-wide border shrink-0 ${
                      gw.status === 'attacked'
                        ? 'bg-rose-950/60 border-rose-800 text-rose-400'
                        : gw.status === 'taken_down'
                        ? 'bg-amber-950/60 border-amber-800 text-amber-400'
                        : gw.status === 'fixing'
                        ? 'bg-blue-950/60 border-blue-800 text-blue-300'
                        : gw.status === 'restored'
                        ? 'bg-emerald-950/60 border-emerald-800 text-emerald-400'
                        : 'bg-slate-800 border-slate-700 text-slate-300'
                    }`}
                  >
                    {gw.status.replace('_', ' ')}
                  </span>
                </div>

                {/* HORIZONTAL LIFECYCLE STEPPER */}
                <div className="space-y-1 pt-0.5">
                  <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500">
                    Lifecycle Progression
                  </div>
                  <div className="grid grid-cols-4 gap-1 font-mono text-[10px]">
                    {[
                      { key: 'attacked', label: 'Attacked' },
                      { key: 'taken_down', label: 'Down' },
                      { key: 'fixing', label: 'Fixing' },
                      { key: 'restored', label: 'Restored' },
                    ].map((st) => {
                      const isCurrent = gw.status === st.key;
                      const isPast = stepIndex > STATUS_STEPS.indexOf(st.key);

                      return (
                        <button
                          key={st.key}
                          onClick={() => handleStatusChange(gw.id, st.key)}
                          disabled={updatingId === gw.id}
                          className={`py-1 rounded text-center font-medium border transition disabled:opacity-50 ${
                            isCurrent
                              ? 'bg-slate-700 border-slate-600 text-white font-bold'
                              : isPast
                              ? 'bg-slate-900 border-slate-800 text-slate-300 hover:bg-slate-800'
                              : 'bg-slate-950 border-slate-800 text-slate-500 hover:border-slate-700'
                          }`}
                        >
                          {st.label}
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* SAFE TO REOPEN INDICATOR */}
                <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between text-xs font-mono">
                  <span className="text-slate-400">Safe to Reopen:</span>
                  <span
                    className={`px-1.5 py-0.2 rounded text-[10px] font-semibold uppercase tracking-wider border flex items-center space-x-1 ${
                      gw.safe_to_reopen
                        ? 'bg-emerald-950/50 border-emerald-800 text-emerald-300'
                        : 'bg-amber-950/50 border-amber-800 text-amber-300'
                    }`}
                  >
                    {gw.safe_to_reopen ? (
                      <>
                        <CheckCircle className="w-3 h-3 text-emerald-400" />
                        <span>SAFE</span>
                      </>
                    ) : (
                      <>
                        <AlertTriangle className="w-3 h-3 text-amber-400" />
                        <span>HOLD</span>
                      </>
                    )}
                  </span>
                </div>

                {!gw.safe_to_reopen && gw.safe_to_reopen_reasons && gw.safe_to_reopen_reasons.length > 0 && (
                  <p className="text-[10px] font-mono text-amber-400/90 leading-tight truncate">
                    &bull; {gw.safe_to_reopen_reasons[0]}
                  </p>
                )}

                {/* VERIFICATION RESULT (Conditional) */}
                {gw.last_verify_result && (
                  <div className="p-1.5 rounded bg-slate-900/60 border border-slate-800 text-[11px] font-mono flex items-center justify-between">
                    <span className="text-slate-500">Replay Test:</span>
                    <span
                      className={`font-semibold ${
                        gw.last_verify_result.status === 'passed' ? 'text-emerald-400' : 'text-rose-400'
                      }`}
                    >
                      {gw.last_verify_result.summary || gw.last_verify_result.status.toUpperCase()}
                    </span>
                  </div>
                )}
              </div>

              {/* CARD ACTION BUTTONS */}
              <div className="p-2.5 bg-slate-950/90 border-t border-slate-800/80 flex items-center justify-between gap-2 font-mono text-xs">
                <button
                  onClick={() => handleVerifyFix(gw.id)}
                  disabled={verifyingId === gw.id}
                  className="flex-1 py-1 px-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 hover:text-white rounded text-[11px] font-medium flex items-center justify-center space-x-1.5 transition disabled:opacity-50"
                >
                  <ShieldCheck className={`w-3.5 h-3.5 text-slate-300 ${verifyingId === gw.id ? 'animate-spin' : ''}`} />
                  <span>{verifyingId === gw.id ? 'Replaying...' : 'Verify Fix'}</span>
                </button>

                <button
                  onClick={() => setExpandedAdvisoryId(isExpanded ? null : gw.id)}
                  className="py-1 px-2.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 rounded text-[11px] font-medium flex items-center space-x-1 transition"
                  title="View Remediation Advisory"
                >
                  <span>Advisory</span>
                  {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
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
