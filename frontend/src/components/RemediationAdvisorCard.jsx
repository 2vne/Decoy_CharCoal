import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  CheckCircle,
  Circle,
  RefreshCw,
  Info,
  Clock,
  Sparkles,
  User,
  Sliders,
  ExternalLink,
  HelpCircle,
  ArrowRight,
  Shield,
  Activity,
} from 'lucide-react';
import { api } from '../api/client';

export default function RemediationAdvisorCard({
  incidentId = null,
  gatewayId = null,
  onOpenEvent = null,
}) {
  const [advisory, setAdvisory] = useState(null);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [stepStatuses, setStepStatuses] = useState({});
  const [activeTooltip, setActiveTooltip] = useState(null);
  const [error, setError] = useState(null);

  const fetchAdvisory = async (forceRefresh = false) => {
    if (!incidentId && !gatewayId) return;
    if (forceRefresh) setRefreshing(true);
    else setLoading(true);
    setError(null);

    try {
      let data = null;
      if (incidentId) {
        data = forceRefresh
          ? await api.refreshIncidentAdvisory(incidentId)
          : await api.getIncidentAdvisory(incidentId);
      } else if (gatewayId) {
        data = await api.getGatewayAdvisory(gatewayId, forceRefresh);
      }
      if (data) {
        setAdvisory(data);
        if (data.step_statuses) {
          setStepStatuses(data.step_statuses);
        }
      }
    } catch (err) {
      console.error('Failed to load remediation advisory:', err);
      setError(err.message || 'Failed to load advisory');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchAdvisory(false);
  }, [incidentId, gatewayId]);

  const handleToggleStep = async (stepId, currentStatus) => {
    const nextStatus = currentStatus === 'done' ? 'pending' : 'done';
    setStepStatuses((prev) => ({ ...prev, [stepId]: nextStatus }));

    try {
      await api.updateAdvisoryStepStatus(stepId, nextStatus, '', incidentId, gatewayId);
    } catch (err) {
      console.error('Failed to persist step status:', err);
      // Revert on error
      setStepStatuses((prev) => ({ ...prev, [stepId]: currentStatus }));
    }
  };

  if (loading && !advisory) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 flex flex-col items-center justify-center space-y-3 min-h-[220px]">
        <RefreshCw className="w-6 h-6 text-indigo-400 animate-spin" />
        <span className="text-sm font-medium text-slate-300">Evaluating incident logs and matching playbooks...</span>
        <span className="text-xs text-slate-500">Generating AI Remediation Advisory</span>
      </div>
    );
  }

  if (error && !advisory) {
    return (
      <div className="bg-slate-900 border border-red-500/30 rounded-xl p-5 flex items-center justify-between">
        <div className="flex items-center space-x-3 text-red-400">
          <AlertTriangle className="w-5 h-5 flex-shrink-0" />
          <span className="text-sm">{error}</span>
        </div>
        <button
          onClick={() => fetchAdvisory(true)}
          className="px-3 py-1 bg-red-950/60 hover:bg-red-900/60 text-red-300 border border-red-800 rounded text-xs font-semibold"
        >
          Retry
        </button>
      </div>
    );
  }

  if (!advisory) return null;

  const isSimulated = advisory.source?.includes('MOCK') || advisory.source?.includes('TEMPLATE');
  const confidencePct = Math.round((advisory.confidence || 0.85) * 100);

  return (
    <div className="bg-slate-900/95 border border-indigo-500/30 rounded-xl overflow-hidden shadow-2xl backdrop-blur-md transition-all">
      {/* HEADER SECTION */}
      <div className="p-5 bg-gradient-to-r from-indigo-950/60 via-slate-900 to-slate-900 border-b border-indigo-500/20 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-indigo-500/10 border border-indigo-500/30 rounded-lg">
            <Sparkles className="w-5 h-5 text-indigo-400" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h3 className="text-base font-bold text-slate-100 tracking-wide uppercase">
                Remediation Advisor
              </h3>
              {/* SOURCE BADGE */}
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${
                isSimulated
                  ? 'bg-amber-500/10 border-amber-500/30 text-amber-300'
                  : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              }`}>
                {isSimulated ? 'SIMULATED (TEMPLATE)' : 'AI SUGGESTION'}
              </span>
              {/* CONFIDENCE BADGE */}
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-500/10 border border-indigo-500/30 text-indigo-300">
                Confidence: {confidencePct}%
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Automated playbook synthesis & evidence-grounded lifecycle recovery
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          {/* NON-NEGOTIABLE HUMAN REVIEW REQUIRED BADGE */}
          <span className="px-2.5 py-1 rounded-md text-xs font-semibold bg-amber-500/10 border border-amber-500/40 text-amber-300 flex items-center space-x-1.5 shadow-sm">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400 flex-shrink-0" />
            <span>AI suggestion, human review required</span>
          </span>

          <button
            onClick={() => fetchAdvisory(true)}
            disabled={refreshing}
            className="p-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 rounded-lg text-xs font-medium flex items-center space-x-1 transition-all disabled:opacity-50"
            title="Refresh Remediation Advisory"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-indigo-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* SUGGESTED OWNER / GIT ATTRIBUTION BANNER */}
      {advisory.suggested_owner && (
        <div className="px-5 py-2.5 bg-slate-950/70 border-b border-slate-800 flex items-center justify-between text-xs">
          <div className="flex items-center space-x-2 text-slate-300">
            <User className="w-3.5 h-3.5 text-indigo-400 flex-shrink-0" />
            <span className="text-slate-400 font-medium">Suggested Owner:</span>
            <span className="font-mono text-indigo-300 bg-indigo-950/40 px-2 py-0.5 rounded border border-indigo-800/40">
              {advisory.suggested_owner}
            </span>
          </div>
          <span className="text-[11px] text-slate-500 italic">
            Root cause correlation grounded in git telemetry & ownership rules
          </span>
        </div>
      )}

      {/* LIKELY CAUSES SUMMARY */}
      {advisory.likely_causes && advisory.likely_causes.length > 0 && (
        <div className="px-5 py-3 bg-indigo-950/20 border-b border-slate-800">
          <span className="text-[11px] uppercase tracking-wider text-indigo-300 font-bold block mb-1">
            Likely Root Cause Analysis:
          </span>
          <div className="space-y-1.5">
            {advisory.likely_causes.map((cause, idx) => (
              <div key={idx} className="flex items-start justify-between text-xs text-slate-300">
                <div className="flex items-center space-x-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 flex-shrink-0" />
                  <span>{cause.text}</span>
                  <span className="text-[10px] text-indigo-400 font-mono">
                    ({Math.round((cause.confidence || 0.85) * 100)}% conf)
                  </span>
                </div>
                {cause.evidence_event_ids && cause.evidence_event_ids.length > 0 && (
                  <div className="flex items-center space-x-1">
                    <span className="text-[10px] text-slate-500">Evidence:</span>
                    {cause.evidence_event_ids.map((evId, eIdx) => (
                      <span
                        key={eIdx}
                        onClick={() => onOpenEvent && onOpenEvent(evId)}
                        className="text-[10px] font-mono bg-slate-800 hover:bg-slate-700 text-slate-300 px-1.5 py-0.5 rounded cursor-pointer border border-slate-700"
                        title={`Click to view event ${evId}`}
                      >
                        #{evId.slice(0, 8)}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* MAIN BODY SECTIONS */}
      <div className="p-5 space-y-6 text-sm">
        {/* 1. IMMEDIATE ACTIONS */}
        <div>
          <div className="flex items-center justify-between mb-2.5">
            <h4 className="text-xs font-bold uppercase tracking-wider text-red-400 flex items-center space-x-1.5">
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>1. Immediate Containment Actions</span>
            </h4>
            <span className="text-[11px] text-slate-500">Human execution checklist</span>
          </div>

          <div className="space-y-2">
            {advisory.immediate_actions?.map((item, idx) => {
              const stepKey = `imm_${item.playbook_id}_${idx}`;
              const isDone = stepStatuses[stepKey] === 'done';
              const showTooltip = activeTooltip === stepKey;

              return (
                <div
                  key={stepKey}
                  className={`p-3 rounded-lg border transition-all ${
                    isDone
                      ? 'bg-slate-950/40 border-emerald-900/40 opacity-75'
                      : 'bg-slate-800/40 border-slate-700/60 hover:border-slate-600'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-start space-x-3">
                      <button
                        onClick={() => handleToggleStep(stepKey, stepStatuses[stepKey] || 'pending')}
                        className="mt-0.5 text-slate-400 hover:text-emerald-400 transition-colors"
                      >
                        {isDone ? (
                          <CheckCircle className="w-4 h-4 text-emerald-400" />
                        ) : (
                          <Circle className="w-4 h-4 text-slate-500" />
                        )}
                      </button>
                      <div>
                        <span className={`text-xs font-medium ${isDone ? 'line-through text-slate-400' : 'text-slate-200'}`}>
                          {item.step}
                        </span>
                        {item.why && (
                          <p className="text-[11px] text-slate-400 mt-1 flex items-start space-x-1">
                            <Info className="w-3 h-3 text-indigo-400 mt-0.5 flex-shrink-0" />
                            <span>{item.why}</span>
                          </p>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center space-x-1.5 flex-shrink-0">
                      {item.playbook_id && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-indigo-950/60 border border-indigo-800/50 text-indigo-300">
                          {item.playbook_id}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* 2. BEFORE REOPENING */}
        <div>
          <div className="flex items-center justify-between mb-2.5">
            <h4 className="text-xs font-bold uppercase tracking-wider text-amber-400 flex items-center space-x-1.5">
              <Clock className="w-3.5 h-3.5" />
              <span>2. Before Reopening (Hardening Verification Gate)</span>
            </h4>
            <span className="text-[11px] text-slate-500">Must be addressed before traffic restoration</span>
          </div>

          <div className="space-y-2">
            {advisory.before_reopening?.map((item, idx) => {
              const stepKey = `bef_${item.playbook_id}_${idx}`;
              const isDone = stepStatuses[stepKey] === 'done';

              return (
                <div
                  key={stepKey}
                  className={`p-3 rounded-lg border transition-all ${
                    isDone
                      ? 'bg-slate-950/40 border-emerald-900/40 opacity-75'
                      : 'bg-slate-800/40 border-slate-700/60 hover:border-slate-600'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-start space-x-3">
                      <button
                        onClick={() => handleToggleStep(stepKey, stepStatuses[stepKey] || 'pending')}
                        className="mt-0.5 text-slate-400 hover:text-emerald-400 transition-colors"
                      >
                        {isDone ? (
                          <CheckCircle className="w-4 h-4 text-emerald-400" />
                        ) : (
                          <Circle className="w-4 h-4 text-slate-500" />
                        )}
                      </button>
                      <div>
                        <span className={`text-xs font-medium ${isDone ? 'line-through text-slate-400' : 'text-slate-200'}`}>
                          {item.step}
                        </span>
                        {item.why && (
                          <p className="text-[11px] text-slate-400 mt-1">
                            {item.why}
                          </p>
                        )}
                      </div>
                    </div>

                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-950/40 border border-amber-800/40 text-amber-300">
                      {item.playbook_id || 'gate'}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* 3. STAGED REOPEN PLAN */}
        {advisory.staged_reopen_plan && advisory.staged_reopen_plan.length > 0 && (
          <div>
            <div className="flex items-center justify-between mb-2.5">
              <h4 className="text-xs font-bold uppercase tracking-wider text-cyan-400 flex items-center space-x-1.5">
                <Sliders className="w-3.5 h-3.5" />
                <span>3. Staged Reopen Plan</span>
              </h4>
              <span className="text-[11px] text-slate-500">Phased canary ramp</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {advisory.staged_reopen_plan.map((phase, idx) => (
                <div
                  key={idx}
                  className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg flex flex-col justify-between space-y-2 relative overflow-hidden"
                >
                  <div className="absolute top-0 right-0 w-12 h-12 bg-cyan-500/5 rounded-bl-full pointer-events-none" />
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                        Phase {idx + 1}
                      </span>
                      <span className="px-1.5 py-0.5 bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 rounded text-[10px] font-bold">
                        {phase.traffic_percent}% Traffic
                      </span>
                    </div>
                    <span className="text-xs font-semibold text-slate-200 block mt-1">
                      {phase.phase}
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] uppercase tracking-wider text-slate-500 block mb-0.5 font-bold">
                      Exit Criteria:
                    </span>
                    <span className="text-[11px] text-slate-300">
                      {phase.exit_criteria}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* 4. MONITORING AFTER RESTORE & LONG-TERM FIXES */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Post-Restore Monitoring */}
          <div className="p-3.5 bg-slate-950/50 border border-slate-800 rounded-lg space-y-2">
            <h5 className="text-xs font-bold uppercase tracking-wider text-indigo-300 flex items-center space-x-1.5">
              <Activity className="w-3.5 h-3.5" />
              <span>4. After-Restore Monitoring</span>
            </h5>
            <div className="space-y-1.5">
              {advisory.monitoring_after_restore?.map((item, idx) => (
                <div key={idx} className="flex items-start space-x-2 text-xs text-slate-300">
                  <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 mt-1.5 flex-shrink-0" />
                  <div>
                    <span className="font-medium text-slate-200">{item.step}</span>
                    {item.why && <p className="text-[10px] text-slate-400">{item.why}</p>}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Long-Term Hardening */}
          <div className="p-3.5 bg-slate-950/50 border border-slate-800 rounded-lg space-y-2">
            <h5 className="text-xs font-bold uppercase tracking-wider text-emerald-300 flex items-center space-x-1.5">
              <Shield className="w-3.5 h-3.5" />
              <span>5. Long-Term Fixes</span>
            </h5>
            <div className="space-y-1.5">
              {advisory.long_term_fixes?.map((item, idx) => (
                <div key={idx} className="flex items-start space-x-2 text-xs text-slate-300">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mt-1.5 flex-shrink-0" />
                  <div>
                    <span className="font-medium text-slate-200">{item.step}</span>
                    {item.why && <p className="text-[10px] text-slate-400">{item.why}</p>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* RE-ATTACK RISK & CAVEATS */}
        <div className="p-3.5 bg-amber-950/20 border border-amber-900/30 rounded-lg space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-amber-300 uppercase tracking-wide flex items-center space-x-1.5">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
              <span>Re-Attack Risk: {advisory.reattack_risk?.level || 'MEDIUM'}</span>
            </span>
          </div>

          {advisory.reattack_risk?.reasons && advisory.reattack_risk.reasons.length > 0 && (
            <ul className="list-disc list-inside text-xs text-amber-200/80 space-y-0.5">
              {advisory.reattack_risk.reasons.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          )}

          {advisory.caveats && advisory.caveats.length > 0 && (
            <div className="pt-2 border-t border-amber-900/20 text-[11px] text-slate-400 space-y-0.5">
              {advisory.caveats.map((c, i) => (
                <p key={i}>&bull; {c}</p>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

