import React, { useState, useEffect } from 'react';
import {
  Shield,
  LayoutDashboard,
  Users,
  Server,
  CreditCard,
  KeyRound,
  LogOut,
  ExternalLink,
  Bell,
  CheckCircle2,
  Sliders,
  ChevronDown,
  Terminal,
} from 'lucide-react';
import { BASE_URL, api } from '../api/client';

export default function PortalLayout({
  user,
  currentTab,
  onTabChange,
  onLogout,
  basePath,
  setBasePath,
  children,
}) {
  const [envDropdownOpen, setEnvDropdownOpen] = useState(false);
  const [backendConnected, setBackendConnected] = useState(true);

  useEffect(() => {
    let unmounted = false;
    const probe = async () => {
      const res = await api.checkHealth();
      if (!unmounted) {
        setBackendConnected(res.ok);
      }
    };
    probe();
    const interval = setInterval(probe, 5000);
    return () => {
      unmounted = true;
      clearInterval(interval);
    };
  }, []);

  const navItems = [
    { id: 'dashboard', label: 'Operations Dashboard', icon: LayoutDashboard },
    { id: 'customers', label: 'Customers & Tenants', icon: Users },
    { id: 'admin', label: 'Infrastructure Console', icon: Server },
    { id: 'billing', label: 'Billing & Subscriptions', icon: CreditCard },
    { id: 'reset', label: 'Access Recovery', icon: KeyRound },
  ];

  const isDecoy = basePath === '/demo/decoy';

  return (
    <div className="min-h-screen bg-slate-50 text-slate-800 flex flex-col font-sans antialiased">
      {/* Top Navbar */}
      <header className="bg-slate-900 border-b border-slate-800 text-white sticky top-0 z-40 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          {/* Left Brand */}
          <div className="flex items-center space-x-6">
            <div className="flex items-center space-x-2.5 cursor-pointer" onClick={() => onTabChange('dashboard')}>
              <div className="h-9 w-9 rounded-lg bg-blue-600 flex items-center justify-center shadow-md shadow-blue-500/20 ring-1 ring-blue-400">
                <Shield className="h-5 w-5 text-white" />
              </div>
              <div>
                <span className="text-lg font-black tracking-tight text-white block leading-none">
                  SENTINEL<span className="text-blue-400 font-normal">PORTAL</span>
                </span>
                <span className="text-[10px] font-mono tracking-wider text-slate-400 uppercase">
                  Enterprise Cloud Console
                </span>
              </div>
            </div>

            {/* Environment Badge / Switcher */}
            <div className="relative">
              <button
                type="button"
                onClick={() => setEnvDropdownOpen(!envDropdownOpen)}
                className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-semibold border transition ${
                  isDecoy
                    ? 'bg-amber-950/80 border-amber-500 text-amber-200'
                    : 'bg-blue-950/80 border-blue-500 text-blue-200'
                }`}
              >
                <span className={`h-2 w-2 rounded-full ${isDecoy ? 'bg-amber-400 animate-pulse' : 'bg-blue-400'}`} />
                <span>{isDecoy ? 'Sandbox Instance [DECOY]' : 'Production [REAL]'}</span>
                <ChevronDown className="w-3 h-3 ml-0.5 opacity-70" />
              </button>

              {envDropdownOpen && (
                <div className="absolute left-0 mt-2 w-56 rounded-xl bg-slate-950 border border-slate-800 shadow-2xl p-1.5 z-50 text-xs">
                  <div className="px-2 py-1 text-[10px] font-mono text-slate-400 uppercase tracking-wider">
                    Target Application Route
                  </div>
                  <button
                    onClick={() => {
                      setBasePath('/demo/decoy');
                      setEnvDropdownOpen(false);
                    }}
                    className={`w-full text-left px-2.5 py-2 rounded-lg font-medium transition flex items-center justify-between ${
                      isDecoy ? 'bg-amber-950 text-amber-200' : 'text-slate-300 hover:bg-slate-900'
                    }`}
                  >
                    <div>
                      <div className="font-semibold">Decoy Honeynet</div>
                      <div className="text-[10px] text-slate-400">/demo/decoy/* (Telemetry Traps)</div>
                    </div>
                    {isDecoy && <CheckCircle2 className="w-4 h-4 text-amber-400" />}
                  </button>

                  <button
                    onClick={() => {
                      setBasePath('/demo/real');
                      setEnvDropdownOpen(false);
                    }}
                    className={`w-full text-left px-2.5 py-2 rounded-lg font-medium transition flex items-center justify-between ${
                      !isDecoy ? 'bg-blue-950 text-blue-200' : 'text-slate-300 hover:bg-slate-900'
                    }`}
                  >
                    <div>
                      <div className="font-semibold">Real Application</div>
                      <div className="text-[10px] text-slate-400">/demo/real/* (Trusted Core)</div>
                    </div>
                    {!isDecoy && <CheckCircle2 className="w-4 h-4 text-blue-400" />}
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Right User & Links */}
          <div className="flex items-center space-x-4">
            {/* Backend Connectivity Status Badge */}
            <div
              className={`hidden sm:flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-medium border transition ${
                backendConnected
                  ? 'bg-emerald-950/70 border-emerald-500/40 text-emerald-300'
                  : 'bg-rose-950/80 border-rose-500/50 text-rose-300 animate-pulse'
              }`}
            >
              <span className={`h-2 w-2 rounded-full ${backendConnected ? 'bg-emerald-400' : 'bg-rose-500 animate-ping'}`} />
              <span>{backendConnected ? 'Backend Connected' : 'Backend Disconnected'}</span>
            </div>

            {/* Link back to SOC Dashboard */}
            <a
              href="/"
              target="_blank"
              rel="noopener noreferrer"
              className="hidden sm:flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-mono bg-slate-800/80 hover:bg-slate-700 text-slate-300 transition border border-slate-700"
              title="Open the SOC Security Analyst command center in another window"
            >
              <Terminal className="w-3.5 h-3.5 text-cyan-400" />
              <span>SOC Dashboard</span>
              <ExternalLink className="w-3 h-3 text-slate-400" />
            </a>

            {/* User Profile */}
            <div className="flex items-center space-x-3 pl-2 border-l border-slate-800">
              <div className="h-8 w-8 rounded-full bg-blue-600 text-white font-bold flex items-center justify-center text-xs shadow-inner">
                {user?.email ? user.email[0].toUpperCase() : 'U'}
              </div>
              <div className="hidden md:block text-left text-xs">
                <div className="font-semibold text-slate-200 truncate max-w-[140px]">
                  {user?.user || user?.email?.split('@')[0] || 'Administrator'}
                </div>
                <div className="text-[10px] text-slate-400 capitalize">{user?.role || 'Super Admin'}</div>
              </div>

              <button
                onClick={onLogout}
                title="Sign out of enterprise portal"
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main App Container */}
      <div className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 flex flex-col md:flex-row gap-6">
        {/* Navigation Sidebar */}
        <aside className="w-full md:w-64 flex-shrink-0">
          <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm space-y-1">
            <div className="px-3 py-2 text-[11px] font-mono uppercase tracking-wider text-slate-400">
              Enterprise Navigation
            </div>
            {navItems.map((item) => {
              const Icon = item.icon;
              const active = currentTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onTabChange(item.id)}
                  className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-xs font-semibold transition text-left ${
                    active
                      ? 'bg-blue-600 text-white shadow-sm'
                      : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
                  }`}
                >
                  <Icon className={`w-4 h-4 ${active ? 'text-white' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </div>

          {/* Infrastructure Health Sidebar Card */}
          <div className="mt-4 bg-white border border-slate-200 rounded-xl p-4 shadow-sm text-xs space-y-2 hidden md:block">
            <div className="flex items-center justify-between text-slate-500 font-medium">
              <span>SaaS Gateway Ingress</span>
              <span className={`h-2 w-2 rounded-full ${backendConnected ? 'bg-emerald-500' : 'bg-rose-500 animate-pulse'}`} />
            </div>
            <div className="text-slate-900 font-bold">{BASE_URL.replace(/^https?:\/\//, '')}</div>
            <div className="text-[11px] text-slate-400">
              {backendConnected
                ? 'High-availability reverse proxy with automated honeynet diversion policy.'
                : 'Connection to backend lost. Polling health endpoints for automatic recovery...'}
            </div>
          </div>
        </aside>

        {/* Content Workspace */}
        <main className="flex-1 min-w-0">
          {children}
        </main>
      </div>

      {/* Footer */}
      <footer className="bg-white border-t border-slate-200 py-4 text-center text-xs text-slate-400">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row justify-between items-center gap-2">
          <span>&copy; 2026 SENTINEL PORTAL Technologies Inc. All rights reserved.</span>
          <span className="font-mono text-[11px]">Enterprise SaaS Security Platform v3.4.1</span>
        </div>
      </footer>
    </div>
  );
}

