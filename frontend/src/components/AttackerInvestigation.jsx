import React, { useState, useEffect, useRef } from 'react';
import {
  X,
  Shield,
  AlertTriangle,
  Terminal,
  Activity,
  Share2,
  Lock,
  Unlock,
  Loader2,
  Play,
  Pause,
  RotateCcw,
  Clock,
  MapPin,
  CheckCircle2,
  ExternalLink,
  ChevronRight,
  ChevronDown,
  AlertOctagon,
} from 'lucide-react';
import { api } from '../api/client';
import { useSoc } from '../context/SocContext';

const TABS = [
  { id: 'profile', label: 'PROFILE' },
  { id: 'risk', label: 'RISK SCORE' },
  { id: 'timeline', label: 'TIMELINE' },
  { id: 'mitre', label: 'MITRE ATT&CK' },
  { id: 'replay', label: 'COMMAND REPLAY' },
  { id: 'actions', label: 'ACTIONS & BLOCK' },
  { id: 'incidents', label: 'INCIDENTS' },
];

const FACTOR_DANGERS = {
  scan: [
    'Maps exposed open ingress network services',
    'Precursor probe for automated targeted CVE exploit scripts',
  ],
  brute_force: [
    'High velocity credential exhaustion against SSH/RDP/Web',
    'Indicates adversary equipped with targeted enterprise password dictionaries',
  ],
  login_success: [
    'CRITICAL: Valid authentication breached on honeypot',
    'Grants attacker interactive execution capabilities on the host',
  ],
  recon: [
    'Active host discovery of shadow passwords, local users, and adapter IPs',
    'Prepares ground for credential dumping and internal network pivoting',
  ],
  download_upload: [
    'Ingress tool transfer fetching secondary-stage weaponized implants',
    'C2 dropper staging binary onto local temporary filesystem',
  ],
  persistence: [
    'Survives system reboots through crontabs, rc.local, or systemd services',
    'Ensures long-term unauthenticated backdoor persistence',
  ],
  internal_decoy: [
    'HIGH SEVERITY: Lateral movement detected beyond perimeter',
    'Adversary actively pivoting into sensitive internal enclave systems',
  ],
  multi_honeypot: [
    'Coordinated multi-sensor sweep crossing diverse trap ports',
    'Systematic campaign reconnaissance across infrastructure layers',
  ],
  repeat_attacker: [
    'Identical behavioral command fingerprint detected across different IPs',
    'Correlated persistent threat actor returning via proxy rotation',
  ],
  anomaly: [
    'Isolation Forest model flagged anomalous feature vector',
    'Outlier frequency or timing deviation from baseline traffic',
  ],
  related_high_risk: [
    'Graph correlation with an active critical threat actor',
    'Evidence of synchronized syndicate or shared malware infrastructure',
  ],
};

export default function AttackerInvestigation({ attackerId, onClose, isFullPage = false }) {
  const { attackers, blockAttacker, unblockAttacker, setSelectedAttackerId, blocks } = useSoc();
  const [activeTab, setActiveTab] = useState('profile');
  const [detail, setDetail] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [replaySeq, setReplaySeq] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expandedTechId, setExpandedTechId] = useState(null);

  // Terminal Replay State
  const [replayIndex, setReplayIndex] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const [replaySpeed, setReplaySpeed] = useState(1);
  const replayTimerRef = useRef(null);

  // Live countdown state
  const [countdownSeconds, setCountdownSeconds] = useState(null);
  const [actionLoading, setActionLoading] = useState(false);

  // Load attacker data
  useEffect(() => {
    let unmounted = false;
    async function load() {
      setLoading(true);
      try {
        const [d, t, r] = await Promise.all([
          api.getAttacker(attackerId).catch(() => null),
          api.getAttackerTimeline(attackerId).catch(() => ({ timeline: [] })),
          api.getAttackerReplay(attackerId).catch(() => ({ sequence: [] })),
        ]);

        if (unmounted) return;

        if (d) {
          setDetail(d);
        } else {
          const fallback = attackers.find((a) => a.id === attackerId);
          setDetail(fallback || null);
        }

        setTimeline(t?.timeline || []);
        setReplaySeq(r?.sequence || []);
        setReplayIndex(0);
      } catch (e) {
        console.error('Failed to load attacker dossier:', e);
      } finally {
        if (!unmounted) setLoading(false);
      }
    }
    load();
    return () => {
      unmounted = true;
      if (replayTimerRef.current) clearInterval(replayTimerRef.current);
    };
  }, [attackerId, attackers]);

  // Terminal Replay Player Loop
  useEffect(() => {
    if (!isPlaying) {
      if (replayTimerRef.current) clearInterval(replayTimerRef.current);
      return;
    }

    if (replayIndex >= replaySeq.length) {
      setIsPlaying(false);
      return;
    }

    const currentItem = replaySeq[replayIndex];
    const delay = Math.max(150, (currentItem?.delay_ms || 1000) / replaySpeed);

    replayTimerRef.current = setTimeout(() => {
      setReplayIndex((prev) => prev + 1);
    }, delay);

    return () => clearTimeout(replayTimerRef.current);
  }, [isPlaying, replayIndex, replaySeq, replaySpeed]);

  // Active Block Countdown ticker
  useEffect(() => {
    if (!detail) return;
    const activeBlock = blocks.find((b) => b.ip === detail.ip && b.status === 'active');
    if (!activeBlock || !activeBlock.expires_at) {
      setCountdownSeconds(null);
      return;
    }

    const updateCountdown = () => {
      const diff = Math.max(0, Math.floor((new Date(activeBlock.expires_at).getTime() - Date.now()) / 1000));
      setCountdownSeconds(diff);
    };

    updateCountdown();
    const timer = setInterval(updateCountdown, 1000);
    return () => clearInterval(timer);
  }, [detail, blocks]);

  if (loading) {
    return (
      <div className="fixed inset-y-0 right-0 w-full max-w-2xl bg-soc-surface border-l border-soc-border shadow-2xl p-6 z-50 flex items-center justify-center">
        <div className="text-center font-mono">
          <Activity className="h-8 w-8 text-cyan-400 animate-spin mx-auto mb-2" />
          <div className="text-sm text-soc-muted">LOADING INVESTIGATION DOSSIER...</div>
        </div>
      </div>
    );
  }

  if (!detail) {
    return null;
  }

  const riskBand = detail.risk_band || 'low';
  const riskColor =
    riskBand === 'critical'
      ? '#ef4444'
      : riskBand === 'high'
      ? '#f97316'
      : riskBand === 'medium'
      ? '#eab308'
      : '#10b981';

  return (
    <div
      className={`${
        isFullPage
          ? 'w-full'
          : 'fixed inset-y-0 right-0 w-full max-w-2xl border-l border-soc-border shadow-2xl z-50 flex flex-col'
      } bg-soc-surface`}
    >
      {/* Dossier Header */}
      <div className="p-5 border-b border-soc-border bg-soc-card/70 flex items-start justify-between">
        <div>
          <div className="flex items-center space-x-3">
            <span className="text-lg font-bold font-mono text-white tracking-wider">
              {detail.ip}
            </span>
            <span
              className="px-2 py-0.5 rounded text-xs font-mono font-bold uppercase tracking-wider"
              style={{
                backgroundColor: `${riskColor}22`,
                color: riskColor,
                border: `1px solid ${riskColor}66`,
              }}
            >
              {riskBand} RISK ({detail.risk_score?.toFixed(0)})
            </span>
            {detail.status === 'blocked' && (
              <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-red-950/80 text-red-400 border border-red-500/50 flex items-center space-x-1">
                <Lock className="h-3 w-3" />
                <span>BLOCKED</span>
              </span>
            )}
            {detail.is_repeat && (
              <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-cyan-950/80 text-cyan-300 border border-cyan-500/50">
                REPEAT ACTOR
              </span>
            )}
          </div>
          <div className="text-xs font-mono text-soc-muted mt-1.5 flex items-center space-x-3">
            {detail.geo?.city && (
              <span className="flex items-center space-x-1">
                <MapPin className="h-3 w-3 text-soc-muted" />
                <span>
                  {detail.geo.city}, {detail.geo.country}
                </span>
              </span>
            )}
            <span>Events: {detail.total_events}</span>
            <span>Intent: <strong className="text-cyan-300">{detail.intent || 'reconnaissance'}</strong></span>
          </div>
        </div>

        {!isFullPage && onClose && (
          <button
            onClick={onClose}
            className="p-1 rounded text-soc-muted hover:text-white hover:bg-soc-border/50 transition"
          >
            <X className="h-5 w-5" />
          </button>
        )}
      </div>

      {/* Tabs Header */}
      <div className="flex border-b border-soc-border bg-soc-surface overflow-x-auto">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2.5 text-xs font-mono font-medium whitespace-nowrap transition border-b-2 ${
              activeTab === tab.id
                ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
                : 'border-transparent text-soc-muted hover:text-gray-300'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Contents */}
      <div className="flex-1 overflow-y-auto p-5 space-y-6">
        {/* 1. Profile Tab */}
        {activeTab === 'profile' && (
          <div className="space-y-5 text-xs font-mono">
            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 rounded bg-soc-card border border-soc-border">
                <span className="text-soc-muted block text-[10px] uppercase">First Detected</span>
                <span className="text-white mt-1 block">
                  {detail.first_seen ? new Date(detail.first_seen).toLocaleString() : 'N/A'}
                </span>
              </div>
              <div className="p-3 rounded bg-soc-card border border-soc-border">
                <span className="text-soc-muted block text-[10px] uppercase">Last Activity</span>
                <span className="text-white mt-1 block">
                  {detail.last_seen ? new Date(detail.last_seen).toLocaleString() : 'N/A'}
                </span>
              </div>
            </div>

            <div className="p-3 rounded bg-soc-card border border-soc-border space-y-2">
              <span className="text-soc-muted block text-[10px] uppercase">Deception Footprint</span>
              <div>Honeypots Touched: <span className="text-cyan-300">{detail.honeypots_touched?.join(', ') || 'None'}</span></div>
              <div>Ports Targeted: <span className="text-white">{detail.ports?.join(', ') || 'N/A'}</span></div>
              <div>Autonomous System / ISP: <span className="text-white">{detail.geo?.isp || 'Unknown'}</span></div>
            </div>

            {/* Behavioral Fingerprint */}
            <div className="p-3 rounded bg-soc-card border border-soc-border space-y-2">
              <span className="text-soc-muted block text-[10px] uppercase">Behavioral Fingerprint (SHA256)</span>
              <div className="p-2 rounded bg-black/50 text-[11px] text-cyan-400 break-all border border-soc-border">
                {detail.fingerprint || 'Computing telemetry fingerprint...'}
              </div>
            </div>

            {/* Credentials & Commands Observed */}
            <div className="space-y-3">
              <div className="p-3 rounded bg-soc-card border border-soc-border">
                <span className="text-soc-muted block text-[10px] uppercase mb-1.5">Usernames Attempted</span>
                <div className="flex flex-wrap gap-1.5">
                  {detail.usernames?.length ? (
                    detail.usernames.map((u, i) => (
                      <span key={i} className="px-2 py-0.5 rounded bg-soc-surface border border-soc-border text-white text-[11px]">
                        {u}
                      </span>
                    ))
                  ) : (
                    <span className="text-soc-muted">None captured</span>
                  )}
                </div>
              </div>

              <div className="p-3 rounded bg-soc-card border border-soc-border">
                <span className="text-soc-muted block text-[10px] uppercase mb-1.5">Observed Shell Commands</span>
                <div className="space-y-1 max-h-36 overflow-y-auto">
                  {detail.commands?.length ? (
                    detail.commands.map((cmd, i) => (
                      <div key={i} className="p-1.5 rounded bg-black/60 text-emerald-400 text-[11px] font-mono border border-soc-border/50">
                        $ {cmd}
                      </div>
                    ))
                  ) : (
                    <span className="text-soc-muted">No commands executed</span>
                  )}
                </div>
              </div>
            </div>

            {/* Related Attackers */}
            {detail.related_attackers?.length > 0 && (
              <div className="p-3 rounded bg-soc-card border border-soc-border space-y-2">
                <span className="text-soc-muted block text-[10px] uppercase">Correlated Entities</span>
                <div className="space-y-1.5">
                  {detail.related_attackers.map((rel) => (
                    <div
                      key={rel.id}
                      onClick={() => setSelectedAttackerId(rel.id)}
                      className="p-2 rounded bg-soc-surface border border-soc-border hover:border-cyan-500 cursor-pointer flex items-center justify-between transition"
                    >
                      <div className="flex items-center space-x-2">
                        <Share2 className="h-3.5 w-3.5 text-cyan-400" />
                        <span className="text-white font-medium">{rel.ip}</span>
                      </div>
                      <span className="text-orange-400 font-bold">{rel.risk_score?.toFixed(0)} Risk</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* 2. Risk Tab with "Why Dangerous" Bullet Lists */}
        {activeTab === 'risk' && (
          <div className="space-y-5">
            {/* Animated Risk Gauge */}
            <div className="p-6 rounded bg-soc-card border border-soc-border text-center">
              <div className="relative inline-flex items-center justify-center">
                <svg className="w-36 h-36 transform -rotate-90">
                  <circle
                    cx="72"
                    cy="72"
                    r="58"
                    stroke="#1b253b"
                    strokeWidth="12"
                    fill="transparent"
                  />
                  <circle
                    cx="72"
                    cy="72"
                    r="58"
                    stroke={riskColor}
                    strokeWidth="12"
                    strokeDasharray={364}
                    strokeDashoffset={364 - (364 * (detail.risk_score || 0)) / 100}
                    strokeLinecap="round"
                    fill="transparent"
                    className="transition-all duration-1000 ease-out"
                  />
                </svg>
                <div className="absolute flex flex-col items-center">
                  <span className="text-3xl font-bold font-mono text-white">
                    {detail.risk_score?.toFixed(0)}
                  </span>
                  <span className="text-[10px] font-mono uppercase font-bold" style={{ color: riskColor }}>
                    {riskBand}
                  </span>
                </div>
              </div>
              <div className="text-xs font-mono text-soc-muted mt-3">
                Score computed via additive, explainable deception factor ladder.
              </div>
            </div>

            {/* Factor breakdown with Why Dangerous bullet lists */}
            <div className="space-y-2">
              <div className="text-xs font-mono text-soc-muted uppercase tracking-wider">
                Contributing Risk Factors & Threat Mechanics
              </div>
              <div className="space-y-3">
                {detail.risk_factors?.length ? (
                  detail.risk_factors.map((f, idx) => {
                    const dangers = FACTOR_DANGERS[f.factor] || [
                      'Elevated threat activity observed against honeypot decoys.',
                    ];

                    return (
                      <div
                        key={idx}
                        className="p-3.5 rounded bg-soc-card border border-soc-border space-y-2 text-xs font-mono"
                      >
                        <div className="flex items-start justify-between space-x-3">
                          <div>
                            <div className="font-bold text-white uppercase text-sm">
                              {f.factor.replace('_', ' ')}
                            </div>
                            <div className="text-cyan-300 text-[11px] mt-0.5">{f.reason}</div>
                          </div>
                          <span className="px-2 py-0.5 rounded bg-red-950/50 text-red-400 font-bold border border-red-500/30 whitespace-nowrap">
                            +{f.points} PTS
                          </span>
                        </div>

                        {/* Why Dangerous bullet list */}
                        <div className="p-2.5 rounded bg-black/40 border border-soc-border/60 space-y-1">
                          <span className="text-[10px] uppercase font-bold text-red-400 block">
                            Why this is dangerous:
                          </span>
                          <ul className="list-disc list-inside space-y-0.5 text-soc-muted text-[11px]">
                            {dangers.map((d, dIdx) => (
                              <li key={dIdx} className="text-gray-300">{d}</li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    );
                  })
                ) : (
                  <div className="text-xs font-mono text-soc-muted p-4 text-center">
                    No elevated risk factors detected yet.
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* 3. Timeline Tab */}
        {activeTab === 'timeline' && (
          <div className="space-y-4 font-mono text-xs">
            <div className="text-soc-muted text-xs uppercase tracking-wider mb-2">
              Chronological Kill Chain Progression
            </div>
            <div className="relative pl-6 border-l border-soc-border space-y-4">
              {timeline.length ? (
                timeline.map((ev, i) => (
                  <div key={ev.id || i} className="relative group">
                    <div className="absolute -left-[31px] top-1 h-3 w-3 rounded-full bg-cyan-500 border-2 border-soc-surface shadow-[0_0_8px_#00f0ff]" />
                    <div className="p-3 rounded bg-soc-card border border-soc-border hover:border-cyan-500/50 transition">
                      <div className="flex items-center justify-between text-[11px] text-soc-muted mb-1">
                        <span>{new Date(ev.timestamp).toLocaleTimeString()}</span>
                        <span className="text-cyan-400 uppercase">{ev.honeypot} ({ev.decoy_type})</span>
                      </div>
                      <div className="font-bold text-white uppercase">{ev.event_type}</div>
                      {ev.command && (
                        <div className="mt-1.5 p-1.5 rounded bg-black/60 text-emerald-400 text-[11px]">
                          $ {ev.command}
                        </div>
                      )}
                      {ev.username && (
                        <div className="mt-1 text-soc-muted text-[11px]">User: {ev.username}</div>
                      )}
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-soc-muted text-xs p-4">No timeline events recorded.</div>
              )}
            </div>
          </div>
        )}

        {/* 4. MITRE ATT&CK Tab with Clickable Expandable Evidence */}
        {activeTab === 'mitre' && (
          <div className="space-y-3 font-mono text-xs">
            <div className="text-soc-muted text-xs uppercase tracking-wider">
              Mapped MITRE ATT&CK Matrix (Click technique to inspect evidence)
            </div>
            <div className="space-y-2">
              {detail.mitre?.length ? (
                detail.mitre.map((m, idx) => {
                  const isExpanded = expandedTechId === m.technique_id;
                  return (
                    <div
                      key={idx}
                      className="p-3 rounded bg-soc-card border border-soc-border space-y-2 cursor-pointer hover:border-cyan-500/50 transition"
                      onClick={() => setExpandedTechId(isExpanded ? null : m.technique_id)}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-cyan-300 flex items-center space-x-1.5">
                          {isExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                          <span>{m.technique_id} &mdash; {m.technique_name}</span>
                        </span>
                        <span className="px-2 py-0.5 rounded bg-purple-950/60 border border-purple-500/40 text-purple-300 text-[10px] font-bold">
                          {m.tactic}
                        </span>
                      </div>

                      <div className="text-[11px] text-soc-muted">
                        Evidence linked: <span className="text-white font-bold">{m.evidence_event_ids?.length || 1} telemetry event(s)</span>
                      </div>

                      {/* Expandable Evidence Events List */}
                      {isExpanded && (
                        <div className="mt-2 p-2.5 rounded bg-black/70 border border-soc-border/80 space-y-1.5" onClick={(e) => e.stopPropagation()}>
                          <span className="text-[10px] text-cyan-400 font-bold uppercase block">
                            Triggering Telemetry Event IDs:
                          </span>
                          <div className="space-y-1">
                            {m.evidence_event_ids?.map((evId, eIdx) => (
                              <div key={eIdx} className="text-[11px] text-gray-300 font-mono flex items-center justify-between">
                                <span>&bull; {evId}</span>
                                <span className="text-emerald-400 text-[10px]">VERIFIED EVIDENCE</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })
              ) : (
                <div className="text-soc-muted text-xs p-4 text-center">
                  No MITRE ATT&CK techniques triggered.
                </div>
              )}
            </div>
          </div>
        )}

        {/* 5. Terminal Replay Tab */}
        {activeTab === 'replay' && (
          <div className="space-y-4 font-mono text-xs">
            <div className="flex items-center justify-between p-3 rounded bg-soc-card border border-soc-border">
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => setIsPlaying(!isPlaying)}
                  className="px-3 py-1.5 rounded bg-cyan-950 border border-cyan-500 text-cyan-300 font-bold flex items-center space-x-1.5 hover:bg-cyan-900 transition"
                >
                  {isPlaying ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5 fill-current" />}
                  <span>{isPlaying ? 'PAUSE' : 'PLAY REPLAY'}</span>
                </button>
                <button
                  onClick={() => {
                    setIsPlaying(false);
                    setReplayIndex(0);
                  }}
                  className="p-1.5 rounded bg-soc-surface border border-soc-border text-soc-muted hover:text-white"
                  title="Reset"
                >
                  <RotateCcw className="h-4 w-4" />
                </button>
              </div>

              <div className="flex items-center space-x-2">
                <span className="text-soc-muted text-[10px]">SPEED:</span>
                {[1, 2, 5].map((s) => (
                  <button
                    key={s}
                    onClick={() => setReplaySpeed(s)}
                    className={`px-2 py-0.5 rounded text-[10px] ${
                      replaySpeed === s
                        ? 'bg-cyan-500 text-black font-bold'
                        : 'bg-soc-surface border border-soc-border text-soc-muted'
                    }`}
                  >
                    {s}x
                  </button>
                ))}
              </div>
            </div>

            <div className="rounded border border-soc-border bg-black p-4 scanlines min-h-[260px] font-mono text-xs">
              <div className="flex items-center space-x-2 mb-3 border-b border-gray-800 pb-2 text-[10px] text-gray-500">
                <span className="h-2.5 w-2.5 rounded-full bg-red-500 inline-block" />
                <span className="h-2.5 w-2.5 rounded-full bg-yellow-500 inline-block" />
                <span className="h-2.5 w-2.5 rounded-full bg-green-500 inline-block" />
                <span className="ml-2 text-gray-400">SESSION TTY REPLAY &mdash; {detail.ip}</span>
              </div>

              <div className="space-y-2">
                {replaySeq.slice(0, replayIndex + 1).map((step, idx) => (
                  <div key={idx} className="space-y-0.5">
                    <div className="text-gray-500 text-[10px]">
                      [{new Date(step.timestamp).toLocaleTimeString()}] on {step.honeypot} (delta: +{step.delay_ms}ms)
                    </div>
                    <div className="text-emerald-400">
                      <span className="text-cyan-400 font-bold">{step.username}@honeypot:~$</span> {step.command}
                    </div>
                  </div>
                ))}

                {replayIndex < replaySeq.length && isPlaying && (
                  <span className="inline-block w-2 h-4 bg-emerald-400 animate-pulse" />
                )}

                {replaySeq.length === 0 && (
                  <div className="text-gray-500 text-center py-8">
                    No shell command events recorded for this attacker.
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* 6. Actions Tab with Verified Tick & Rollback Countdown */}
        {activeTab === 'actions' && (
          <div className="space-y-4 font-mono text-xs">
            <div className="p-4 rounded bg-soc-card border border-soc-border space-y-4">
              <div className="text-soc-muted text-xs uppercase tracking-wider">Automated Containment & Firewall Enforcement</div>
              
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-bold text-white text-sm">Target Status: {detail.status.toUpperCase()}</div>
                  <div className="text-soc-muted text-[11px] mt-0.5">
                    {detail.status === 'blocked' ? 'Active firewall drop policy enforced at border' : 'Traffic monitored on deception decoys'}
                  </div>
                </div>

                {detail.status === 'blocked' ? (
                  <button
                    disabled={actionLoading}
                    onClick={async () => {
                      setActionLoading(true);
                      try {
                        await unblockAttacker(detail.id, detail.ip);
                      } finally {
                        setActionLoading(false);
                      }
                    }}
                    className="px-4 py-2 rounded bg-emerald-950 border border-emerald-500 text-emerald-300 font-bold flex items-center space-x-1.5 hover:bg-emerald-900 transition disabled:opacity-60"
                  >
                    {actionLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Unlock className="h-4 w-4" />}
                    <span>MANUAL UNBLOCK</span>
                  </button>
                ) : (
                  <button
                    disabled={actionLoading}
                    onClick={async () => {
                      setActionLoading(true);
                      try {
                        await blockAttacker(detail.id, detail.ip);
                      } finally {
                        setActionLoading(false);
                      }
                    }}
                    className="px-4 py-2 rounded bg-red-950 border border-red-500 text-red-300 font-bold flex items-center space-x-1.5 hover:bg-red-900 transition disabled:opacity-60"
                  >
                    {actionLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Lock className="h-4 w-4" />}
                    <span>ENFORCE BLOCK</span>
                  </button>
                )}
              </div>

              {/* Verified Active Tick & Countdown */}
              {detail.status === 'blocked' && (
                <div className="p-3 rounded bg-black/60 border border-emerald-500/40 flex items-center justify-between">
                  <div className="flex items-center space-x-2 text-emerald-400">
                    <CheckCircle2 className="h-4 w-4 text-emerald-400 animate-pulse" />
                    <span className="font-bold">VERIFIED ACTIVE BY FIREWALL ENFORCER</span>
                  </div>
                  {countdownSeconds !== null && (
                    <div className="flex items-center space-x-1 text-red-400 font-mono font-bold">
                      <Clock className="h-3.5 w-3.5" />
                      <span>ROLLBACK IN: {Math.floor(countdownSeconds / 60)}:{String(countdownSeconds % 60).padStart(2, '0')}</span>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Block History */}
            {detail.blocks?.length > 0 && (
              <div className="space-y-2">
                <span className="text-soc-muted text-xs uppercase tracking-wider">Block Enforcement Log</span>
                {detail.blocks.map((b) => (
                  <div key={b.id} className="p-3 rounded bg-soc-card border border-soc-border text-[11px] space-y-1">
                    <div className="flex justify-between items-center">
                      <span className="font-bold text-white">Block #{b.id} &mdash; {b.status.toUpperCase()}</span>
                      <span className="text-soc-muted">TTL: {b.ttl_seconds}s</span>
                    </div>
                    <div className="text-soc-muted">Requested: {new Date(b.requested_at).toLocaleString()}</div>
                    {b.verified_at && (
                      <div className="text-emerald-400 flex items-center space-x-1">
                        <CheckCircle2 className="h-3 w-3" />
                        <span>Verified: {new Date(b.verified_at).toLocaleTimeString()}</span>
                      </div>
                    )}
                    {b.expires_at && <div className="text-soc-muted">Expires: {new Date(b.expires_at).toLocaleString()}</div>}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* 7. Incidents Tab */}
        {activeTab === 'incidents' && (
          <div className="space-y-3 font-mono text-xs">
            <div className="text-soc-muted text-xs uppercase tracking-wider">Associated Incident Cases</div>
            {detail.incidents?.length ? (
              detail.incidents.map((inc) => (
                <div key={inc.id} className="p-3 rounded bg-soc-card border border-soc-border space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white">{inc.title}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-red-950 border border-red-500/50 text-red-300">
                      {inc.status}
                    </span>
                  </div>
                  <div className="text-soc-muted text-[11px]">
                    Created: {new Date(inc.created_at).toLocaleString()}
                  </div>
                </div>
              ))
            ) : (
              <div className="text-soc-muted text-xs p-4 text-center">
                No incident tickets spawned for this profile yet.
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
