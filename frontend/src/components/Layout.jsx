import React, { useState, useEffect } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  Activity,
  Globe,
  Radio,
  Server,
  AlertTriangle,
  Lock,
  FileText,
  Share2,
  Play,
  Zap,
  CheckCircle2,
  Clock,
  Wifi,
  WifiOff,
  Check,
  AlertOctagon,
  X,
  Info,
  GitBranch,
  Flame,
  Shield,
  ExternalLink,
} from 'lucide-react';
import { useSoc } from '../context/SocContext';
import { BASE_URL } from '../api/client';
import AttackerInvestigation from './AttackerInvestigation';
import NoobAssistantPanel from './NoobAssistantPanel';
import ErrorBoundary from './ErrorBoundary';

export default function Layout() {
  const {
    isDemoMode,
    isLiveConnected,
    loading,
    backendError,
    refreshAllData,
    overview,
    metrics,
    selectedAttackerId,
    setSelectedAttackerId,
    runSimulation,
    toasts,
    narrator,
    setNarrator,
  } = useSoc();

  const [simMenuOpen, setSimMenuOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();

  const navItems = [
    { label: 'Overview', to: '/', icon: Activity },
    { label: 'Live Events', to: '/events', icon: Radio },
    { label: 'Attackers', to: '/attackers', icon: ShieldAlert },
    { label: 'Function Intel', to: '/functions', icon: Zap },
    { label: 'Deception Gateway', to: '/gateway', icon: GitBranch },
    { label: 'Gateway Failures', to: '/failures', icon: Flame },
    { label: 'Threat Universe', to: '/universe', icon: Globe },
    { label: 'Relationship Graph', to: '/relationships', icon: Share2 },
    { label: 'Honeypots', to: '/honeypots', icon: Server },
    { label: 'Incidents', to: '/incidents', icon: AlertTriangle },
    { label: 'Response Center', to: '/response', icon: Lock },
    { label: 'Reports', to: '/reports', icon: FileText },
  ];

  const handleSimulate = (scenario) => {
    runSimulation(scenario, 2.0);
    setSimMenuOpen(false);
  };

  // Keyboard shortcut: Press 'u' to jump to Threat Universe
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (['INPUT', 'TEXTAREA'].includes(e.target.tagName)) return;
      if (e.key === 'u' || e.key === 'U') {
        navigate('/universe');
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [navigate]);

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-soc-bg text-soc-text font-sans">
      {/* Toast Notification Container */}
      <div className="fixed top-4 right-4 z-50 flex flex-col space-y-2 pointer-events-none">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`pointer-events-auto flex items-center space-x-2 px-3 py-2 rounded shadow-md font-mono text-xs border backdrop-blur transition-all duration-300 animate-slide-in ${t.type === 'error'
                ? 'bg-rose-950/90 text-rose-200 border-rose-700'
                : t.type === 'warning'
                  ? 'bg-amber-950/90 text-amber-200 border-amber-700'
                  : t.type === 'success'
                    ? 'bg-emerald-950/90 text-emerald-200 border-emerald-700'
                    : 'bg-slate-900/90 text-slate-200 border-slate-700'
              }`}
          >
            {t.type === 'error' && <AlertOctagon className="h-4 w-4 text-red-400 flex-shrink-0" />}
            {t.type === 'warning' && <AlertTriangle className="h-4 w-4 text-amber-400 flex-shrink-0" />}
            {t.type === 'success' && <Check className="h-4 w-4 text-emerald-400 flex-shrink-0" />}
            {t.type === 'info' && <Info className="h-4 w-4 text-cyan-400 flex-shrink-0" />}
            <span>{t.msg}</span>
          </div>
        ))}
      </div>

      {/* Demo Narrator Overlay (When Full APT Demo runs) */}
      {narrator && (
        <div className="fixed bottom-6 right-6 z-50 p-4 rounded-lg bg-slate-950 border border-slate-700 shadow-xl backdrop-blur max-w-sm font-mono text-xs space-y-2">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <span className="flex items-center space-x-2 text-slate-300 font-bold">
              <span className="h-2 w-2 rounded-full bg-slate-400"></span>
              <span>APT ATTACK NARRATOR</span>
            </span>
            <button onClick={() => setNarrator(null)} className="text-slate-400 hover:text-white">
              <X className="h-4 w-4" />
            </button>
          </div>
          <div className="text-white font-bold text-sm tracking-wide">{narrator.title}</div>
          <div className="text-slate-300 text-[11px] leading-relaxed">{narrator.desc}</div>
          <div className="flex items-center justify-between pt-2 border-t border-slate-800 text-[10px] text-slate-500">
            <span>STEP {narrator.step} / 5</span>
            <span className="text-emerald-400">AUTOMATED AUDIT ACTIVE</span>
          </div>
        </div>
      )}

      {/* Sidebar */}
      <aside className="w-64 flex-shrink-0 flex flex-col border-r border-slate-800 bg-slate-950 z-20">
        {/* Brand Header */}
        <div className="p-4 border-b border-slate-800">
          <div className="flex items-center space-x-2.5">
            <div className="h-8 w-8 rounded bg-cyan-950/60 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-sm">
              <Shield className="h-4 w-4 text-cyan-400" />
            </div>
            <div>
              <div className="text-sm font-bold tracking-widest text-white font-mono">MIRAGE</div>
              <div className="flex items-center space-x-1.5 mt-0.5">
                <span className="relative flex h-1.5 w-1.5">
                  <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-400"></span>
                </span>
                <span className="text-[10px] uppercase font-mono tracking-wider text-emerald-400 font-medium">
                  SYSTEM ONLINE
                </span>
              </div>
            </div>
          </div>
          <div className="text-[10px] text-slate-400 font-mono mt-2 tracking-tight">
            DECEPTION-DRIVEN INTELLIGENCE
          </div>
        </div>

        {/* Navigation links */}
        <nav className="flex-1 overflow-y-auto p-3 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.to;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                className={`flex items-center space-x-3 px-3 py-2 rounded text-xs font-medium transition-all ${isActive
                    ? 'bg-slate-800 text-white font-semibold border border-slate-700'
                    : 'text-slate-400 hover:text-white hover:bg-slate-900'
                  }`}
              >
                <Icon className={`h-4 w-4 ${isActive ? 'text-slate-100' : 'text-slate-500'}`} />
                <span>{item.label}</span>
              </NavLink>
            );
          })}

          <div className="pt-2 mt-2 border-t border-soc-border/40">
            <a
              href="/portal"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center justify-between px-3 py-2 rounded text-xs font-medium text-slate-300 hover:text-white bg-slate-900 hover:bg-slate-800 border border-slate-800 transition-all"
              title="Launch the customer-facing SaaS Decoy Portal in a new browser tab"
            >
              <div className="flex items-center space-x-2.5">
                <Shield className="h-4 w-4 text-amber-400" />
                <span>Decoy SaaS Portal</span>
              </div>
              <ExternalLink className="h-3.5 w-3.5 text-amber-400/80" />
            </a>
          </div>
        </nav>

        {/* Sidebar Footer / Simulation Launcher */}
        <div className="p-3 border-t border-soc-border bg-soc-bg/40 relative">
          <div className="relative">
            <button
              onClick={() => setSimMenuOpen(!simMenuOpen)}
              className="w-full flex items-center justify-center space-x-2 py-2 px-3 rounded bg-slate-900 border border-slate-700 text-rose-400 text-xs font-mono font-medium hover:bg-slate-800 transition"
            >
              <Play className="h-3.5 w-3.5 fill-current" />
              <span>LAUNCH ATTACK</span>
            </button>

            {simMenuOpen && (
              <div className="absolute bottom-full left-0 right-0 mb-2 p-1.5 rounded border border-soc-border bg-soc-surface shadow-2xl space-y-1 z-30">
                <div className="text-[10px] font-mono text-soc-muted px-2 py-1 uppercase tracking-wider">
                  Select Scenario
                </div>
                {[
                  { id: 'full_chain', label: 'Full Kill Chain (APT)', desc: 'Low -> Critical (Lateral Movement)' },
                  { id: 'brute_forcer', label: 'SSH Brute Force', desc: 'Cowrie credential stuffing' },
                  { id: 'noise_scanner', label: 'Noise Mass Scanner', desc: 'Low risk wide port sweep' },
                  { id: 'repeat_attacker', label: 'Repeat Attacker', desc: 'Same fingerprint from new IP' },
                  { id: 'coordinated', label: '3-IP Syndicate', desc: 'Shared credentials & C2 malware' },
                ].map((sc) => (
                  <button
                    key={sc.id}
                    onClick={() => handleSimulate(sc.id)}
                    className="w-full text-left px-2.5 py-1.5 rounded hover:bg-soc-card text-xs transition"
                  >
                    <div className="font-mono text-cyan-300 font-medium">{sc.label}</div>
                    <div className="text-[10px] text-soc-muted">{sc.desc}</div>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col h-screen overflow-hidden">
        {/* Top Navbar */}
        <header className="h-14 border-b border-soc-border bg-soc-surface/80 backdrop-blur px-6 flex items-center justify-between z-10">
          <div className="flex items-center space-x-6 text-xs font-mono">
            {/* Live WebSocket Status */}
            <div className="flex items-center space-x-2">
              {isLiveConnected ? (
                <>
                  <Wifi className="h-4 w-4 text-emerald-400 animate-pulse" />
                  <span className="text-emerald-400 font-medium">LIVE WS CONNECTED</span>
                </>
              ) : (
                <>
                  <WifiOff className="h-4 w-4 text-amber-400" />
                  <span className="text-amber-400 font-medium">RECONNECTING WS...</span>
                </>
              )}
            </div>

            {/* Active Blocks */}
            <div className="flex items-center space-x-2 text-soc-muted border-l border-soc-border pl-4">
              <Lock className="h-3.5 w-3.5 text-red-400" />
              <span>ACTIVE BLOCKS:</span>
              <span className="text-white font-bold bg-red-950/60 border border-red-500/30 px-2 py-0.5 rounded text-[11px]">
                {overview?.active_blocks ?? 0}
              </span>
            </div>

            {/* Average TTD */}
            <div className="hidden lg:flex items-center space-x-2 text-soc-muted border-l border-soc-border pl-4">
              <Clock className="h-3.5 w-3.5 text-cyan-400" />
              <span>AVG TTD:</span>
              <span className="text-cyan-300 font-bold">
                {metrics?.ttd_avg !== null && metrics?.ttd_avg !== undefined
                  ? `${metrics.ttd_avg}s`
                  : 'N/A'}
              </span>
            </div>

            {/* Average TTR */}
            <div className="hidden lg:flex items-center space-x-2 text-soc-muted border-l border-soc-border pl-4">
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
              <span>AVG TTR:</span>
              <span className="text-emerald-300 font-bold">
                {metrics?.ttr_avg !== null && metrics?.ttr_avg !== undefined
                  ? `${metrics.ttr_avg}s`
                  : 'N/A'}
              </span>
            </div>
          </div>

          <div className="flex items-center space-x-4">
            <span className="text-[11px] font-mono text-soc-muted hidden sm:inline">
              Press <kbd className="px-1.5 py-0.5 bg-soc-card border border-soc-border rounded text-cyan-300 font-bold">U</kbd> for Universe
            </span>

            {/* Demo / Backend Offline badge */}
            {backendError ? (
              <span className="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-950/80 text-red-400 border border-red-500/40 animate-pulse">
                <AlertTriangle className="h-3 w-3 text-red-400" />
                <span>BACKEND OFFLINE</span>
              </span>
            ) : isDemoMode ? (
              <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950/80 text-amber-400 border border-amber-500/40 animate-pulse">
                DEMO DATA (BACKEND OFFLINE)
              </span>
            ) : null}

            <div className="text-xs font-mono text-soc-muted">
              {new Date().toLocaleTimeString()} UTC
            </div>
          </div>
        </header>

        {/* Viewport Router Outlet */}
        <main className="flex-1 overflow-y-auto relative p-6">
          {backendError && (
            <div className="mb-6 p-4 rounded border border-rose-800/80 bg-rose-950/30 text-rose-300 font-mono text-xs flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
              <div className="flex items-center space-x-3">
                <AlertTriangle className="h-5 w-5 text-red-400 shrink-0 animate-bounce" />
                <div>
                  <div className="font-bold text-red-200 uppercase tracking-wide">
                    Backend Service Unavailable
                  </div>
                  <div className="text-[11px] text-red-300/80 mt-0.5">
                    Unable to reach FastAPI backend at <code className="text-cyan-300 bg-black/60 px-1 py-0.5 rounded">{BASE_URL}</code> ({backendError})
                  </div>
                </div>
              </div>
              <button
                onClick={refreshAllData}
                className="px-3 py-1.5 rounded bg-red-900/60 border border-red-500/50 hover:bg-red-800 text-white font-mono text-xs font-semibold transition shrink-0 self-end sm:self-auto"
              >
                RETRY CONNECTION
              </button>
            </div>
          )}
          <ErrorBoundary>
            <Outlet />
          </ErrorBoundary>
        </main>
      </div>

      {/* Global Slide-in Attacker Investigation Panel */}
      {selectedAttackerId && (
        <AttackerInvestigation
          attackerId={selectedAttackerId}
          onClose={() => setSelectedAttackerId(null)}
        />
      )}

      {/* Professional Collapsible Noob SOC Assistant Panel */}
      <NoobAssistantPanel />
    </div>
  );
}
