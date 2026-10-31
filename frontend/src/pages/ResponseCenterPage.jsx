import React, { useState, useEffect } from 'react';
import {
  Lock,
  Unlock,
  Shield,
  Clock,
  AlertOctagon,
  CheckCircle,
  XCircle,
  FileDown,
  Play,
  RotateCcw,
  Sparkles,
  Layers,
} from 'lucide-react';
import { useSoc } from '../context/SocContext';
import { api } from '../api/client';

export default function ResponseCenterPage() {
  const {
    blocks,
    actions,
    unblockAttacker,
    blockAttacker,
    approveAction,
    rejectAction,
    setSelectedAttackerId,
    attackers,
    addToast,
  } = useSoc();

  const [filter, setFilter] = useState('all');
  const [manualIp, setManualIp] = useState('');
  const [manualTtl, setManualTtl] = useState(600);

    // What-If Simulator state
    const [whatIfAttackerId, setWhatIfAttackerId] = useState(attackers[0]?.id || 1);
    const [whatIfAction, setWhatIfAction] = useState('block');
    const [whatIfStage, setWhatIfStage] = useState('recon');
    const [whatIfResult, setWhatIfResult] = useState(null);
    const [loadingWhatIf, setLoadingWhatIf] = useState(false);

    useEffect(() => {
      if (attackers.length > 0 && (!whatIfAttackerId || !attackers.some((a) => a.id === whatIfAttackerId))) {
        setWhatIfAttackerId(attackers[0].id);
      }
    }, [attackers, whatIfAttackerId]);

    const filteredBlocks = blocks.filter((b) => {
      if (filter === 'active') return b.status === 'active';
      if (filter === 'rolled_back') return b.status === 'rolled_back';
      return true;
    });

    const proposedActions = actions.filter((a) => a.status === 'proposed');
    const pastActions = actions.filter((a) => a.status !== 'proposed');

    const handleManualBlock = async (e) => {
      e.preventDefault();
      if (!manualIp.trim()) return;
      const targetAtk = attackers.find((a) => a.ip === manualIp.trim());
      const atkId = targetAtk ? targetAtk.id : 999;
      await blockAttacker(atkId, manualIp.trim());
      setManualIp('');
    };

    const handleRunWhatIf = async () => {
      try {
        setLoadingWhatIf(true);
        const res = await api.runWhatIf(parseInt(whatIfAttackerId), whatIfAction, whatIfStage);
        setWhatIfResult(res);
        addToast('Counterfactual simulation evaluated', 'success');
      } catch (e) {
        addToast(`Simulation failed: ${e.message}`, 'error');
      } finally {
        setLoadingWhatIf(false);
      }
    };

    const handleExportIoc = (format) => {
      const url = api.getIocDownloadUrl(format);
      window.open(url, '_blank');
      addToast(`Exporting IOCs as ${format.toUpperCase()}`, 'info');
    };

    return (
              <div className="space-y-6 font-mono text-xs">
                {/* Header & IOC Export Actions */}
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div>
                    <h1 className="text-xl font-bold text-white tracking-wider flex items-center space-x-2">
                      <span>AUTOMATED RESPONSE & CONTAINMENT CENTER</span>
                      <span className="text-xs px-2 py-0.5 rounded bg-red-950 border border-red-500/30 text-red-300 font-bold">
                        {blocks.filter((b) => b.status === 'active').length} ACTIVE BLOCKS
                      </span>
                    </h1>
                    <p className="text-xs text-soc-muted mt-0.5">
                      Human-in-the-loop approval ladder, firewall enforcer registry, and counterfactual what-if analysis
                    </p>
                  </div>

                  {/* IOC Export Buttons */}
                  <div className="flex items-center space-x-2">
                    <span className="text-[11px] text-soc-muted mr-1">EXPORT IOCs:</span>
                    <button
                      onClick={() => handleExportIoc('json')}
                      className="flex items-center space-x-1 px-2.5 py-1 rounded bg-soc-card border border-soc-border text-cyan-300 hover:border-cyan-400 transition"
                    >
                      <FileDown className="h-3 w-3" />
                      <span>JSON</span>
                    </button>
                    <button
                      onClick={() => handleExportIoc('csv')}
                      className="flex items-center space-x-1 px-2.5 py-1 rounded bg-soc-card border border-soc-border text-cyan-300 hover:border-cyan-400 transition"
                    >
                      <FileDown className="h-3 w-3" />
                      <span>CSV</span>
                    </button>
                    <button
                      onClick={() => handleExportIoc('stix')}
                      className="flex items-center space-x-1 px-2.5 py-1 rounded bg-soc-card border border-soc-border text-cyan-300 hover:border-cyan-400 transition"
                    >
                      <FileDown className="h-3 w-3" />
                      <span>STIX 2.1</span>
                    </button>
                  </div>
                </div>

                {/* Human-in-the-Loop Pending Approvals Queue */}
                <div className="p-4 rounded border border-amber-500/40 bg-soc-card space-y-3 shadow-lg">
                  <div className="flex items-center justify-between border-b border-soc-border pb-2">
                    <div className="flex items-center space-x-2 text-amber-300 font-bold">
                      <AlertOctagon className="h-4 w-4" />
                      <span>HUMAN-IN-THE-LOOP ACTION APPROVAL QUEUE</span>
                    </div>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-amber-950 border border-amber-500/40 text-amber-200 font-bold">
                      {proposedActions.length} PENDING APPROVAL
                    </span>
                </div>

                {proposedActions.length > 0 ? (
                  <div className="space-y-2">
                    {proposedActions.map((act) => (
                      <div
                        key={act.id}
                        className="p-3 rounded bg-soc-surface border border-soc-border flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                      >
                        <div>
                          <div className="flex items-center space-x-2">
                            <span className="font-bold text-white uppercase text-xs">{act.action_type.replace('_', ' ')}</span>
                            <span className="text-cyan-300 font-bold">{act.target_ip}</span>
                            <span className="text-soc-muted text-[10px]">(Duration: {act.duration_seconds}s)</span>
                          </div>
                          <div className="text-soc-muted text-[11px] mt-0.5">{act.reason}</div>
                        </div>

                        <div className="flex items-center space-x-2">
                          <button
                            onClick={() => approveAction(act.id)}
                            className="flex items-center space-x-1 px-3 py-1.5 rounded bg-emerald-950 border border-emerald-500 text-emerald-300 hover:bg-emerald-900 transition font-bold"
                          >
                            <CheckCircle className="h-3.5 w-3.5" />
                            <span>APPROVE & ENFORCE</span>
                          </button>
                          <button
                            onClick={() => rejectAction(act.id, 'Declined by analyst')}
                            className="flex items-center space-x-1 px-3 py-1.5 rounded bg-red-950 border border-red-500/50 text-red-300 hover:bg-red-900 transition font-bold"
                          >
                            <XCircle className="h-3.5 w-3.5" />
                            <span>REJECT</span>
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-soc-muted py-3 text-center text-[11px]">
                    No proposed actions pending approval. Critical score &ge;90 threats are auto-contained.
                  </div>
                )}
              </div>

                  {/* What-If Counterfactual Simulator Panel */ }
                  < div className = "p-4 rounded border border-cyan-500/40 bg-soc-card space-y-4 shadow-xl" >
        <div className="flex items-center justify-between border-b border-soc-border pb-2">
          <div className="flex items-center space-x-2 text-cyan-300 font-bold">
            <Sparkles className="h-4 w-4" />
            <span>COUNTERFACTUAL WHAT-IF SIMULATOR</span>
          </div>
          <span className="text-[10px] text-soc-muted">Compare actual vs alternative containment trajectories</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 items-end">
          <div>
            <label className="text-[10px] text-soc-muted uppercase block mb-1">Target Attacker</label>
            <select
              value={whatIfAttackerId}
              onChange={(e) => setWhatIfAttackerId(e.target.value)}
              className="w-full bg-soc-surface border border-soc-border rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-cyan-500"
            >
              {attackers.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.ip} (Risk {a.risk_score?.toFixed(0)})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="text-[10px] text-soc-muted uppercase block mb-1">Intervention Action</label>
            <select
              value={whatIfAction}
              onChange={(e) => setWhatIfAction(e.target.value)}
              className="w-full bg-soc-surface border border-soc-border rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="block">Firewall Block</option>
              <option value="delay">Rate Limit / Tar-Pit</option>
              <option value="none">No Action (Baseline)</option>
            </select>
          </div>

          <div>
            <label className="text-[10px] text-soc-muted uppercase block mb-1">Intervention Stage</label>
            <select
              value={whatIfStage}
              onChange={(e) => setWhatIfStage(e.target.value)}
              className="w-full bg-soc-surface border border-soc-border rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="recon">Reconnaissance (Stage 1)</option>
              <option value="brute_force">Brute Force (Stage 2)</option>
              <option value="privilege_escalation">Privilege Escalation (Stage 3)</option>
              <option value="malware_staging">Malware Dropper (Stage 4)</option>
              <option value="lateral_movement">Lateral Movement (Stage 5)</option>
            </select>
          </div>

          <button
            onClick={handleRunWhatIf}
            disabled={loadingWhatIf}
            className="w-full py-1.5 px-3 rounded bg-cyan-950 border border-cyan-400 text-cyan-200 font-bold hover:bg-cyan-900 transition flex items-center justify-center space-x-1.5"
          >
            <Play className={`h-3.5 w-3.5 fill-current ${loadingWhatIf ? 'animate-spin' : ''}`} />
            <span>RUN SIMULATION</span>
          </button>
        </div>

        { whatIfResult && (
                    <div className="p-3.5 rounded bg-black/60 border border-cyan-500/30 space-y-3 mt-3">
                      <div className="grid grid-cols-3 gap-2 text-center border-b border-gray-800 pb-2">
                        <div>
                          <span className="text-[10px] text-soc-muted block">Actual Risk Score</span>
                          <span className="text-red-400 font-bold text-base">{whatIfResult.actual_risk?.toFixed(0)}</span>
                        </div>
                        <div>
                          <span className="text-[10px] text-soc-muted block">Projected Risk</span>
                          <span className="text-emerald-400 font-bold text-base">{whatIfResult.projected_risk?.toFixed(0)}</span>
                        </div>
                        <div>
                          <span className="text-[10px] text-soc-muted block">Risk Reduction</span>
                          <span className="text-cyan-300 font-bold text-base">{whatIfResult.risk_reduction_pct}%</span>
                        </div>
                      </div>

                      <p className="text-cyan-200 text-[11px] leading-relaxed">{whatIfResult.estimated_impact}</p>

                      <div className="space-y-1">
                        <span className="text-[10px] text-soc-muted uppercase block">Counterfactual Kill Chain Comparison:</span>
                        <div className="grid grid-cols-1 sm:grid-cols-5 gap-2">
                          {whatIfResult.counterfactual_comparison?.map((st, i) => (
                            <div key={i} className="p-2 rounded bg-soc-surface border border-soc-border text-[10px]">
                              <div className="font-bold text-white capitalize">{st.stage.replace('_', ' ')}</div>
                              <div className="text-soc-muted mt-1">Actual: <span className="text-gray-300">{st.actual_status}</span></div>
                              <div className="mt-0.5">
                                Alt: <span className={st.counterfactual_status === 'prevented' ? 'text-emerald-400 font-bold' : 'text-gray-300'}>
                                  {st.counterfactual_status}
                                </span>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
              </div>

                              {/* Manual Immediate Block Form */}
                              <form onSubmit={handleManualBlock} className="p-4 rounded border border-soc-border bg-soc-card flex flex-wrap items-center gap-3">
                                <span className="text-white font-bold uppercase text-xs flex items-center space-x-1.5">
                                  <Lock className="h-4 w-4 text-red-400" />
                                  <span>Manual Firewall Block:</span>
                                </span>
                                <input
                                  type="text"
                                  value={manualIp}
                                  onChange={(e) => setManualIp(e.target.value)}
                                  placeholder="Enter IP to block immediately (e.g. 198.51.100.2)..."
                                  className="flex-1 min-w-[220px] bg-soc-surface border border-soc-border rounded px-3 py-1.5 text-white placeholder-soc-muted focus:outline-none focus:border-red-500"
                                />
                                <input
                                  type="number"
                                  value={manualTtl}
                                  onChange={(e) => setManualTtl(parseInt(e.target.value) || 600)}
                                  className="w-24 bg-soc-surface border border-soc-border rounded px-2 py-1.5 text-white"
                                  title="TTL in seconds"
                                />
                                <button
                                  type="submit"
                                  className="px-4 py-1.5 rounded bg-red-950 border border-red-500 text-red-300 hover:bg-red-900 transition font-bold"
                                >
                                  ENFORCE BLOCK
                                </button>
                              </form>

                              {/* Active & Historical Blocks Table */}
                              <div className="space-y-3">
                                <div className="flex items-center justify-between">
                                  <div className="flex items-center space-x-2">
                                    {['all', 'active', 'rolled_back'].map((f) => (
                                      <button
                                        key={f}
                                        onClick={() => setFilter(f)}
                                        className={`px-3 py-1 rounded uppercase font-bold text-[11px] transition ${filter === f
                                            ? 'bg-cyan-500 text-black'
                                            : 'bg-soc-card border border-soc-border text-soc-muted hover:text-white'
                                          }`}
                                      >
                                        {f.replace('_', ' ')}
                                      </button>
                                    ))}
                                  </div>
                                  <span className="text-soc-muted text-[11px]">Auto-rollback evaluates every 5s</span>
                                </div>

                                <div className="rounded border border-soc-border bg-soc-surface overflow-hidden shadow-2xl">
                                  <table className="w-full text-left">
                                    <thead className="bg-soc-card/90 text-soc-muted border-b border-soc-border">
                                      <tr>
                                        <th className="py-3 px-4">BLOCK ID</th>
                                        <th className="py-3 px-4">TARGET IP</th>
                                        <th className="py-3 px-4">REQUESTED BY</th>
                                        <th className="py-3 px-4">TTL (SECONDS)</th>
                                        <th className="py-3 px-4">STATUS</th>
                                        <th className="py-3 px-4">VERIFIED AT</th>
                                        <th className="py-3 px-4 text-right">ACTION</th>
                                      </tr>
                                    </thead>
                                    <tbody className="divide-y divide-soc-border/60">
                                      {filteredBlocks.map((b) => (
                                        <tr key={b.id} className="hover:bg-soc-card/50 transition">
                                          <td className="py-3 px-4 text-soc-muted">#{b.id}</td>
                                          <td className="py-3 px-4 font-bold text-white">
                                            <span
                                              onClick={() => b.attacker_id && setSelectedAttackerId(b.attacker_id)}
                                              className="hover:text-cyan-300 hover:underline cursor-pointer"
                                            >
                                              {b.ip}
                                            </span>
                                </td>
                                <td className="py-3 px-4 text-soc-muted">{b.requested_by}</td>
                                <td className="py-3 px-4 text-white">{b.ttl_seconds}s</td>
                                <td className="py-3 px-4">
                                  {b.status === 'active' ? (
                                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-950 text-red-400 border border-red-500/40 flex items-center space-x-1 w-max">
                                      <Lock className="h-2.5 w-2.5" />
                                      <span>ACTIVE</span>
                                    </span>
                                  ) : (
                                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-soc-card text-soc-muted border border-soc-border flex items-center space-x-1 w-max">
                                      <RotateCcw className="h-2.5 w-2.5" />
                                      <span>ROLLED BACK</span>
                                    </span>
                                  )}
                                </td>
                                <td className="py-3 px-4 text-soc-muted">
                                  {b.verified_at ? new Date(b.verified_at).toLocaleTimeString() : 'Verified (Mock)'}
                                </td>
                                <td className="py-3 px-4 text-right">
                                  {b.status === 'active' && (
                                    <button
                                      onClick={() => unblockAttacker(b.attacker_id, b.ip)}
                                      className="px-2.5 py-1 rounded bg-emerald-950 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-900 transition text-[11px] font-medium"
                                    >
                                      ROLLBACK NOW
                                    </button>
                                  )}
                                </td>
                              </tr>
              ))}
                            </tbody>
          </table>
                      </div>
      </div>
              </div>
              );
}
