import React, { useState, useEffect } from 'react';
import {
  FileText,
  Download,
  BarChart3,
  Clock,
  CheckCircle,
  AlertOctagon,
  ShieldAlert,
  Activity,
  Layers,
  Sparkles,
  Loader2,
  AlertTriangle,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
} from 'recharts';
import { useSoc } from '../context/SocContext';
import { api } from '../api/client';

export default function ReportsPage() {
  const { metrics, overview, addToast } = useSoc();
  const [summaryData, setSummaryData] = useState(null);
  const [exposureAssets, setExposureAssets] = useState([]);
  const [healthCorrelation, setHealthCorrelation] = useState(null);
  const [advisories, setAdvisories] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchReportData = () => {
    setLoading(true);
    setError(null);
    Promise.allSettled([
      api.getReportsSummary(),
      api.getExposureBudget(),
      api.getHealthCorrelation(),
      api.getAdaptiveDeception(),
    ]).then(([sumRes, expRes, hcRes, advRes]) => {
      let failedCount = 0;
      if (sumRes.status === 'fulfilled') setSummaryData(sumRes.value);
      else failedCount++;

      if (expRes.status === 'fulfilled') setExposureAssets(expRes.value || []);
      else failedCount++;

      if (hcRes.status === 'fulfilled') setHealthCorrelation(hcRes.value);
      else failedCount++;

      if (advRes.status === 'fulfilled') setAdvisories(advRes.value?.advisories || []);
      else failedCount++;

      if (failedCount === 4) {
        setError('Failed to fetch analytics from backend.');
      }
    }).finally(() => {
      setLoading(false);
    });
  };

  useEffect(() => {
    fetchReportData();
  }, []);

  const handleUpdateThreshold = async (assetId, newThreshold) => {
    try {
      const updated = await api.updateExposureBudget([{ id: assetId, threshold: newThreshold }]);
      setExposureAssets(updated);
      addToast('Exposure budget threshold updated', 'success');
    } catch (e) {
      addToast(`Failed to update threshold: ${e.message}`, 'error');
    }
  };

  if (loading && !summaryData && !healthCorrelation) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] space-y-4 font-mono">
        <Loader2 className="h-10 w-10 text-cyan-400 animate-spin" />
        <div className="text-sm text-cyan-300 font-bold tracking-wider animate-pulse">
          AGGREGATING EXECUTIVE SOC METRICS & EXPOSURE BUDGET...
        </div>
        <p className="text-xs text-soc-muted">
          Retrieving telemetry models from backend
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white tracking-wider">
            EXECUTIVE SOC THREAT & DECEPTION REPORT
          </h1>
          <p className="text-soc-muted mt-0.5">
            Deception ROI, security exposure budget, and infrastructure health correlation analytics
          </p>
        </div>

        <button
          onClick={() => window.print()}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-soc-card border border-soc-border text-cyan-300 hover:border-cyan-400 transition"
        >
          <Download className="h-3.5 w-3.5" />
          <span>PRINT / EXPORT REPORT</span>
        </button>
      </div>

      {error && (
        <div className="p-3.5 rounded border border-red-500/40 bg-red-950/40 text-red-300 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
          <button
            onClick={fetchReportData}
            className="px-2.5 py-1 rounded bg-red-900 border border-red-500 text-white font-bold text-[11px]"
          >
            RETRY
          </button>
        </div>
      )}

      {/* KPI Cards: MTTD, MTTR, Suppression, Success Rate */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded border border-soc-border bg-soc-card">
          <span className="text-soc-muted text-[10px] uppercase block">Mean Time to Detect (MTTD)</span>
          <span className="text-2xl font-bold text-cyan-400 mt-2 block">
            {summaryData?.mttd_seconds ? `${summaryData.mttd_seconds}s` : (metrics?.ttd_avg ? `${metrics.ttd_avg}s` : '0.0s')}
          </span>
          <span className="text-[10px] text-soc-muted mt-1 block">From honeypot touch to triage</span>
        </div>

        <div className="p-4 rounded border border-soc-border bg-soc-card">
          <span className="text-soc-muted text-[10px] uppercase block">Mean Time to Respond (MTTR)</span>
          <span className="text-2xl font-bold text-emerald-400 mt-2 block">
            {summaryData?.mttr_seconds ? `${summaryData.mttr_seconds}s` : (metrics?.ttr_avg ? `${metrics.ttr_avg}s` : '0.0s')}
          </span>
          <span className="text-[10px] text-soc-muted mt-1 block">Autonomous containment block</span>
        </div>

        <div className="p-4 rounded border border-soc-border bg-soc-card">
          <span className="text-soc-muted text-[10px] uppercase block">Response Success Rate</span>
          <span className="text-2xl font-bold text-white mt-2 block">
            {summaryData?.response_success_rate !== undefined && summaryData?.response_success_rate !== null
              ? `${summaryData.response_success_rate}%`
              : 'N/A'}
          </span>
          <span className="text-[10px] text-emerald-400 mt-1 block">Enforced without escapes</span>
        </div>

        <div className="p-4 rounded border border-soc-border bg-soc-card">
          <span className="text-soc-muted text-[10px] uppercase block">Alerts Suppressed by De-dup</span>
          <span className="text-2xl font-bold text-yellow-400 mt-2 block">
            {metrics?.alerts_suppressed ?? (summaryData?.alerts_suppressed ?? 0)}
          </span>
          <span className="text-[10px] text-soc-muted mt-1 block">Duplicate packets collapsed (60s)</span>
        </div>
      </div>

      {/* Security Exposure Budget Section */}
      <div className="p-5 rounded border border-soc-border bg-soc-card space-y-4 shadow-xl">
        <div className="flex items-center justify-between border-b border-soc-border pb-2">
          <div className="flex items-center space-x-2 text-cyan-300 font-bold">
            <Layers className="h-4 w-4" />
            <span>SECURITY EXPOSURE BUDGET (SIMULATED ASSETS)</span>
          </div>
          <span className="text-[10px] text-soc-muted">
            Alerts triggered when adversary threat velocity approaches threshold
          </span>
        </div>

        {exposureAssets.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {exposureAssets.map((asset) => {
              const isBreached = asset.breached;
              const pct = Math.min(100, (asset.exposure_score / (asset.threshold || 1)) * 100);

              return (
                <div
                  key={asset.id}
                  className={`p-3.5 rounded border space-y-3 ${
                    isBreached
                      ? 'bg-rose-950/30 border-rose-800'
                      : 'bg-slate-900 border-slate-800'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <h4 className="font-bold text-white text-xs">{asset.name}</h4>
                      <span className="text-[10px] text-soc-muted capitalize">
                        {asset.asset_type?.replace('_', ' ')} &bull; {asset.criticality}
                      </span>
                    </div>
                    {isBreached && (
                      <span className="px-1.5 py-0.2 bg-red-950 border border-red-500 text-red-400 rounded text-[9px] font-bold animate-pulse">
                        BUDGET BREACHED
                      </span>
                    )}
                  </div>

                  <div>
                    <div className="flex justify-between text-[11px] mb-1">
                      <span className="text-soc-muted">Exposure Score:</span>
                      <span className={`font-bold ${isBreached ? 'text-red-400' : 'text-cyan-300'}`}>
                        {asset.exposure_score} / {asset.threshold}
                      </span>
                    </div>
                    <div className="w-full bg-gray-800 rounded-full h-2 overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all duration-500 ${
                          isBreached ? 'bg-red-500' : 'bg-cyan-400'
                        }`}
                        style={{ width: `${pct}%` }}
                      ></div>
                    </div>
                  </div>

                  <div className="flex items-center justify-between text-[10px] text-soc-muted pt-2 border-t border-soc-border/60">
                    <span>
                      Linked Honeypot: <span className="text-white uppercase">{asset.honeypot_link}</span>
                    </span>
                    <button
                      onClick={() => {
                        const next = prompt(`Enter new threshold for ${asset.name}:`, asset.threshold);
                        if (next && !isNaN(next)) handleUpdateThreshold(asset.id, parseFloat(next));
                      }}
                      className="text-cyan-400 hover:underline"
                    >
                      Edit Threshold
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="text-center py-6 text-soc-muted">
            No exposure budget models loaded.
          </div>
        )}
      </div>

      {/* Honeypot Health & Attack Burst Correlation Chart */}
      {healthCorrelation && (
        <div className="p-5 rounded border border-soc-border bg-soc-card space-y-4">
          <div className="flex items-center justify-between border-b border-soc-border pb-2">
            <div className="flex items-center space-x-2 text-cyan-300 font-bold">
              <Activity className="h-4 w-4" />
              <span>SERVICE-HEALTH CORRELATION TELEMETRY</span>
            </div>
            <span className="text-[10px] text-emerald-400 font-bold">
              Coupling Index: {healthCorrelation.overall_coupling_index ?? '0.0'}
            </span>
          </div>

          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={healthCorrelation.timeline || []}>
                <defs>
                  <linearGradient id="eventBurstGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00f0ff" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#00f0ff" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="cpuLoadGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="timestamp" stroke="#64748b" fontSize={10} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0b0f17',
                    border: '1px solid #1b253b',
                    fontFamily: 'JetBrains Mono',
                    fontSize: '11px',
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="event_burst"
                  name="Attack Ingestion Burst"
                  stroke="#00f0ff"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#eventBurstGrad)"
                />
                <Area
                  type="monotone"
                  dataKey="cowrie_cpu"
                  name="Cowrie CPU %"
                  stroke="#ef4444"
                  strokeWidth={1.5}
                  fillOpacity={1}
                  fill="url(#cpuLoadGrad)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]">
            {healthCorrelation.correlations?.map((c) => (
              <div key={c.honeypot} className="p-2.5 rounded bg-soc-surface border border-soc-border flex items-start space-x-2">
                <span className="text-cyan-400 font-bold uppercase">{c.honeypot}:</span>
                <span className="text-soc-muted">{c.insight}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Adaptive Deception Advisories */}
      {advisories.length > 0 && (
        <div className="p-5 rounded border border-purple-500/40 bg-soc-card space-y-3">
          <div className="flex items-center justify-between border-b border-soc-border pb-2">
            <div className="flex items-center space-x-2 text-purple-300 font-bold">
              <Sparkles className="h-4 w-4" />
              <span>ADAPTIVE DECEPTION CONFIGURATION ADVISORIES</span>
            </div>
            <span className="text-[10px] text-purple-400 bg-purple-950 px-2 py-0.5 rounded border border-purple-500/30 font-bold">
              AI HEURISTIC RECOMMENDATIONS
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {advisories.map((ad) => (
              <div key={ad.id} className="p-3.5 rounded bg-soc-surface border border-soc-border space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white uppercase text-xs">
                    {ad.honeypot}: {ad.type?.replace('_', ' ')}
                  </span>
                  <span className="text-emerald-400 font-bold text-[10px]">
                    {ad.confidence ? `${(ad.confidence * 100).toFixed(0)}% Match` : 'Heuristic'}
                  </span>
                </div>
                <div className="text-[11px] text-soc-muted">
                  Current: <span className="text-gray-400 line-through">{ad.current_setting}</span>
                </div>
                <div className="text-[11px] text-cyan-300">
                  Recommended: <span className="font-bold">{ad.suggested_setting}</span>
                </div>
                <p className="text-[10px] text-gray-400 mt-1">{ad.impact}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
