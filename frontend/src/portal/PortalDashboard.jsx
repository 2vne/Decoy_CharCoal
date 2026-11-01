import React, { useState, useEffect } from 'react';
import {
  Activity,
  Server,
  Users,
  CreditCard,
  ShieldCheck,
  CheckCircle2,
  Clock,
  ArrowRight,
  TrendingUp,
  AlertTriangle,
  RefreshCw,
  Sliders,
  ExternalLink,
  ChevronRight,
  Shield,
  Layers,
  Zap,
} from 'lucide-react';
import { BASE_URL } from '../api/client';

export default function PortalDashboard({
  user,
  basePath,
  onNavigate,
}) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchDashboard = async () => {
    try {
      setLoading(true);
      setError('');
      const res = await fetch(`${BASE_URL}${basePath}/user/dashboard`);
      if (!res.ok) {
        throw new Error(`Failed to load dashboard: HTTP ${res.status}`);
      }
      const json = await res.json();
      setData(json);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboard();
  }, [basePath]);

  return (
    <div className="space-y-6">
      {/* Top Banner / Welcome Card */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-xl font-bold text-slate-900 tracking-tight">
              Enterprise Operations Workspace
            </h1>
            <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
              Live Production
            </span>
          </div>
          <p className="text-sm text-slate-500 mt-1">
            Logged in as <span className="font-semibold text-slate-800">{user?.email || 'analyst@mirage.local'}</span> ({user?.role || 'Administrator'})
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={fetchDashboard}
            disabled={loading}
            className="px-3 py-2 text-xs font-medium text-slate-600 bg-slate-100 hover:bg-slate-200 rounded-lg transition flex items-center space-x-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Sync Telemetry</span>
          </button>
          <button
            onClick={() => onNavigate('admin')}
            className="px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-lg shadow-sm transition flex items-center space-x-1.5"
          >
            <Server className="w-3.5 h-3.5" />
            <span>Open Cluster Console</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-amber-50 border border-amber-200 text-amber-800 text-xs flex items-center space-x-2">
          <AlertTriangle className="h-4 w-4 text-amber-600 flex-shrink-0" />
          <span>Notice: {error} (Serving synthetic operational baseline)</span>
        </div>
      )}

      {/* KPI Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Service Health */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between text-slate-500 text-xs font-medium mb-1">
            <span>SERVICE HEALTH</span>
            <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
          </div>
          <div className="text-2xl font-bold text-slate-900 capitalize">
            {data?.system_status || 'Operational'}
          </div>
          <div className="text-xs text-emerald-600 flex items-center gap-1 mt-1 font-medium">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>99.98% Gateway SLA</span>
          </div>
        </div>

        {/* Active Sessions */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between text-slate-500 text-xs font-medium mb-1">
            <span>ACTIVE SESSIONS</span>
            <Activity className="w-4 h-4 text-blue-500" />
          </div>
          <div className="text-2xl font-bold text-slate-900">
            {data?.total_active_sessions || 24}
          </div>
          <div className="text-xs text-slate-500 mt-1">
            Encrypted TLS client sessions
          </div>
        </div>

        {/* Managed Tenants */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between text-slate-500 text-xs font-medium mb-1">
            <span>ENTERPRISE TENANTS</span>
            <Users className="w-4 h-4 text-indigo-500" />
          </div>
          <div className="text-2xl font-bold text-slate-900">
            {data?.active_tenants || 3}
          </div>
          <div className="text-xs text-indigo-600 mt-1 font-medium flex items-center gap-1">
            <TrendingUp className="w-3.5 h-3.5" />
            <span>All accounts active</span>
          </div>
        </div>

        {/* Threat Perimeter */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between text-slate-500 text-xs font-medium mb-1">
            <span>API PERIMETER GATEWAY</span>
            <ShieldCheck className="w-4 h-4 text-emerald-500" />
          </div>
          <div className="text-2xl font-bold text-slate-900">
            12 ms
          </div>
          <div className="text-xs text-slate-500 mt-1">
            Average edge evaluation time
          </div>
        </div>
      </div>

      {/* Main Grid: Action Modules & Activity Log */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Enterprise Functional Areas */}
        <div className="lg:col-span-2 space-y-4">
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
            <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider mb-4 flex items-center justify-between">
              <span>Managed Core Capabilities</span>
              <span className="text-xs font-normal text-slate-400">Production Infrastructure Scope</span>
            </h2>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {/* Card 1: Customers */}
              <div
                onClick={() => onNavigate('customers')}
                className="p-4 rounded-xl border border-slate-200 hover:border-blue-400 hover:shadow-md transition-all cursor-pointer bg-slate-50/50 group"
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="h-9 w-9 rounded-lg bg-blue-100 text-blue-600 flex items-center justify-center font-bold">
                    <Users className="w-5 h-5" />
                  </div>
                  <ChevronRight className="w-4 h-4 text-slate-400 group-hover:translate-x-1 group-hover:text-blue-600 transition-all" />
                </div>
                <h3 className="font-semibold text-slate-900 text-sm">Tenant & Customer Directory</h3>
                <p className="text-xs text-slate-500 mt-1">
                  Inspect assigned tenant profiles, compute quotas, and database balances.
                </p>
                <div className="mt-3 text-xs font-medium text-blue-600 flex items-center gap-1">
                  <span>Manage Accounts</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </div>
              </div>

              {/* Card 2: Admin System */}
              <div
                onClick={() => onNavigate('admin')}
                className="p-4 rounded-xl border border-slate-200 hover:border-indigo-400 hover:shadow-md transition-all cursor-pointer bg-slate-50/50 group"
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="h-9 w-9 rounded-lg bg-indigo-100 text-indigo-600 flex items-center justify-center font-bold">
                    <Server className="w-5 h-5" />
                  </div>
                  <ChevronRight className="w-4 h-4 text-slate-400 group-hover:translate-x-1 group-hover:text-indigo-600 transition-all" />
                </div>
                <h3 className="font-semibold text-slate-900 text-sm">Cluster Infrastructure Console</h3>
                <p className="text-xs text-slate-500 mt-1">
                  Review cluster node health, backup topology, and download environment configs.
                </p>
                <div className="mt-3 text-xs font-medium text-indigo-600 flex items-center gap-1">
                  <span>Open Infrastructure</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </div>
              </div>

              {/* Card 3: Billing */}
              <div
                onClick={() => onNavigate('billing')}
                className="p-4 rounded-xl border border-slate-200 hover:border-emerald-400 hover:shadow-md transition-all cursor-pointer bg-slate-50/50 group"
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="h-9 w-9 rounded-lg bg-emerald-100 text-emerald-600 flex items-center justify-center font-bold">
                    <CreditCard className="w-5 h-5" />
                  </div>
                  <ChevronRight className="w-4 h-4 text-slate-400 group-hover:translate-x-1 group-hover:text-emerald-600 transition-all" />
                </div>
                <h3 className="font-semibold text-slate-900 text-sm">Subscription & Charge Ledger</h3>
                <p className="text-xs text-slate-500 mt-1">
                  Execute test payment authorization charges and inspect payment tokens.
                </p>
                <div className="mt-3 text-xs font-medium text-emerald-600 flex items-center gap-1">
                  <span>Review Invoices</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </div>
              </div>

              {/* Card 4: Security Reset */}
              <div
                onClick={() => onNavigate('reset')}
                className="p-4 rounded-xl border border-slate-200 hover:border-amber-400 hover:shadow-md transition-all cursor-pointer bg-slate-50/50 group"
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="h-9 w-9 rounded-lg bg-amber-100 text-amber-600 flex items-center justify-center font-bold">
                    <Shield className="w-5 h-5" />
                  </div>
                  <ChevronRight className="w-4 h-4 text-slate-400 group-hover:translate-x-1 group-hover:text-amber-600 transition-all" />
                </div>
                <h3 className="font-semibold text-slate-900 text-sm">Security Credential Recovery</h3>
                <p className="text-xs text-slate-500 mt-1">
                  Simulate password recovery requests and test timing-safe credential reset paths.
                </p>
                <div className="mt-3 text-xs font-medium text-amber-600 flex items-center gap-1">
                  <span>Access Recovery</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Right 1 Col: Recent Audit & Activity Timeline */}
        <div className="space-y-4">
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
            <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider mb-4 flex items-center justify-between">
              <span>Recent Operational Events</span>
              <Activity className="w-4 h-4 text-slate-400" />
            </h2>

            <div className="space-y-3">
              {(data?.recent_activity || [
                { id: '1', action: 'Primary cluster health checked', time: '4 mins ago', user: 'system' },
                { id: '2', action: 'Customer balance synchronization', time: '28 mins ago', user: 'billing' },
                { id: '3', action: 'SSL edge certificates renewed', time: '2 hours ago', user: 'ingress' },
                { id: '4', action: 'Database backup snapshot verified', time: '5 hours ago', user: 'cron-job' },
              ]).map((act) => (
                <div key={act.id} className="flex items-start space-x-3 text-xs border-b border-slate-100 pb-2.5 last:border-0 last:pb-0">
                  <div className="h-2 w-2 rounded-full bg-blue-500 mt-1.5 flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="font-medium text-slate-800 truncate">{act.action}</div>
                    <div className="text-[11px] text-slate-400 flex items-center gap-1.5 mt-0.5">
                      <span>{act.time}</span>
                      <span>•</span>
                      <span className="font-mono text-slate-500">{act.user}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Quick Support Card */}
          <div className="bg-gradient-to-br from-slate-900 to-slate-800 rounded-xl p-5 text-white shadow-sm">
            <div className="flex items-center space-x-2 text-xs font-semibold uppercase tracking-wider text-blue-400 mb-1">
              <Zap className="w-3.5 h-3.5" />
              <span>Enterprise Support</span>
            </div>
            <h3 className="font-bold text-sm">24/7 SRE Incident Response</h3>
            <p className="text-xs text-slate-300 mt-1">
              Your tenant cluster is backed by an automated 99.99% uptime guarantee with live failover routing.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

