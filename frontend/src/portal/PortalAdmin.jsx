import React, { useState, useEffect } from 'react';
import {
  Server,
  Cpu,
  HardDrive,
  Activity,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Download,
  Copy,
  Check,
  RefreshCw,
  Terminal,
  Key,
  Database,
  Layers,
  Zap,
} from 'lucide-react';

export default function PortalAdmin({ basePath }) {
  const [adminData, setAdminData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [envContent, setEnvContent] = useState('');
  const [envLoading, setEnvLoading] = useState(false);
  const [envModalOpen, setEnvModalOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  const fetchAdminSystem = async () => {
    try {
      setLoading(true);
      setError('');
      const res = await fetch(`${basePath}/admin/system`, {
        headers: {
          Authorization: 'Bearer admin-master-access-token-991',
        },
      });

      if (!res.ok) {
        throw new Error(`Admin endpoint rejected request: HTTP ${res.status}`);
      }

      const json = await res.json();
      setAdminData(json);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleFetchEnvHoneytoken = async () => {
    try {
      setEnvLoading(true);
      const res = await fetch(`${basePath}/.env`);
      const text = await res.text();
      setEnvContent(text);
      setEnvModalOpen(true);
    } catch (err) {
      alert(`Failed to load environment configuration: ${err.message}`);
    } finally {
      setEnvLoading(false);
    }
  };

  const handleCopyEnv = () => {
    navigator.clipboard.writeText(envContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  useEffect(() => {
    fetchAdminSystem();
  }, [basePath]);

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-xl font-bold text-slate-900 tracking-tight">
              Cluster Infrastructure & Administration Console
            </h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-indigo-50 text-indigo-700 border border-indigo-200">
              Restricted Tier
            </span>
          </div>
          <p className="text-sm text-slate-500 mt-1">
            Real-time management for cluster nodes, failover storage, service health, and environment secrets.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={fetchAdminSystem}
            disabled={loading}
            className="px-3 py-2 text-xs font-medium text-slate-600 bg-slate-100 hover:bg-slate-200 rounded-lg transition flex items-center space-x-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Poll Health</span>
          </button>
        </div>
      </div>

      {/* Audit Warning Callout */}
      <div className="p-4 rounded-xl bg-slate-900 text-slate-200 text-xs flex items-start space-x-3 border border-slate-800 shadow-md">
        <Lock className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
        <div className="flex-1">
          <div className="font-semibold text-white">Immutable Administrative Audit Logging Active</div>
          <div className="text-slate-400 mt-0.5">
            {adminData?.notice ||
              'Every API call, diagnostic query, and environment download is recorded with client IP and forensic telemetry.'}
          </div>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-50 border border-red-200 text-red-800 text-xs flex items-center space-x-2">
          <AlertTriangle className="h-4 w-4 text-red-600 flex-shrink-0" />
          <span>Access Warning: {error} (Endpoint telemetry recorded)</span>
        </div>
      )}

      {/* Infrastructure Node & Health Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Card 1: Cluster Nodes */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm space-y-3">
          <div className="flex items-center justify-between text-xs font-semibold text-slate-500 uppercase tracking-wider">
            <span>Cluster Topology</span>
            <Server className="w-4 h-4 text-blue-500" />
          </div>
          <div className="text-2xl font-bold text-slate-900">
            {adminData?.cluster_nodes !== undefined ? `${adminData.cluster_nodes} Active Nodes` : '2 Active Nodes'}
          </div>
          <p className="text-xs text-slate-500">
            Kubernetes managed worker nodes with automated auto-scaling and pod replication.
          </p>

          <div className="space-y-2 pt-2 border-t border-slate-100 text-xs">
            <div className="flex justify-between items-center text-slate-600">
              <span>Node 01 (Master Ingress)</span>
              <span className="font-mono text-emerald-600 font-medium">Ready (2.1% CPU)</span>
            </div>
            <div className="flex justify-between items-center text-slate-600">
              <span>Node 02 (Worker Sandbox)</span>
              <span className="font-mono text-emerald-600 font-medium">Ready (4.8% CPU)</span>
            </div>
          </div>
        </div>

        {/* Card 2: Backup Server */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm space-y-3">
          <div className="flex items-center justify-between text-xs font-semibold text-slate-500 uppercase tracking-wider">
            <span>Disaster Recovery Host</span>
            <Database className="w-4 h-4 text-indigo-500" />
          </div>
          <div className="text-sm font-mono font-bold text-slate-800 truncate">
            {adminData?.backup_server || '10.240.11.90 (Honeynet Subnet)'}
          </div>
          <p className="text-xs text-slate-500">
            Secondary snapshot replication target for live failover and state replication.
          </p>

          <div className="space-y-2 pt-2 border-t border-slate-100 text-xs">
            <div className="flex justify-between items-center text-slate-600">
              <span>Replication Latency</span>
              <span className="font-mono text-slate-900 font-semibold">0.4 ms</span>
            </div>
            <div className="flex justify-between items-center text-slate-600">
              <span>Last Snapshot</span>
              <span className="font-mono text-slate-500">14 mins ago</span>
            </div>
          </div>
        </div>

        {/* Card 3: Service Health */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm space-y-3">
          <div className="flex items-center justify-between text-xs font-semibold text-slate-500 uppercase tracking-wider">
            <span>Subsystem Health</span>
            <Activity className="w-4 h-4 text-emerald-500" />
          </div>
          <div className="text-base font-semibold text-slate-800">
            {adminData?.service_health || 'Operational - All services nominal'}
          </div>
          <p className="text-xs text-slate-500">
            Automated health probes verifying API ingress, database pooling, and gateway route policies.
          </p>

          <div className="space-y-1 pt-2 border-t border-slate-100 text-xs">
            <div className="flex justify-between text-slate-600">
              <span>Memory Utilization:</span>
              <span className="font-mono font-semibold text-slate-800">68%</span>
            </div>
            <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
              <div className="bg-blue-600 h-2 rounded-full" style={{ width: '68%' }} />
            </div>
          </div>
        </div>
      </div>

      {/* Developer Secrets & Configuration File Section (Honeytoken Integration) */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-slate-100 pb-3">
          <div className="flex items-center space-x-2">
            <Key className="w-5 h-5 text-amber-500" />
            <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
              Environment Secrets & Configuration
            </h2>
          </div>
          <span className="text-xs font-mono text-slate-400">Canary Honeytoken Integration</span>
        </div>

        <p className="text-xs text-slate-500 leading-relaxed">
          Application configuration parameters, database connection strings, and API keys are stored in encrypted environment specifications. Authorized administrators can inspect or download the server configuration file below:
        </p>

        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-4 rounded-xl bg-slate-50 border border-slate-200">
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 rounded-lg bg-amber-100 text-amber-700 flex items-center justify-center font-mono font-bold text-xs">
              .env
            </div>
            <div>
              <div className="font-semibold text-xs text-slate-900">Infrastructure Environment File</div>
              <div className="text-[11px] text-slate-400">Contains Database URL, Stripe token, and AWS API keys</div>
            </div>
          </div>

          <button
            onClick={handleFetchEnvHoneytoken}
            disabled={envLoading}
            className="px-4 py-2 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-lg shadow-sm transition flex items-center space-x-2 cursor-pointer disabled:opacity-50"
          >
            <Download className="w-3.5 h-3.5" />
            <span>{envLoading ? 'Retrieving Config...' : 'Inspect Environment (.env)'}</span>
          </button>
        </div>
      </div>

      {/* Environment Config Modal */}
      {envModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-sm p-4">
          <div className="w-full max-w-xl bg-slate-950 rounded-2xl border border-slate-800 shadow-2xl p-6 space-y-4 text-slate-100">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2 text-white font-bold text-sm">
                <Terminal className="w-4 h-4 text-emerald-400" />
                <span>Configuration File: .env (Honeynet Canary)</span>
              </div>
              <button
                onClick={() => setEnvModalOpen(false)}
                className="text-slate-400 hover:text-white text-xs font-mono"
              >
                [ESC]
              </button>
            </div>

            <p className="text-xs text-slate-400">
              The following environment variables were retrieved from the server. Access telemetry has been emitted to the SOC engine:
            </p>

            <div className="relative">
              <pre className="p-4 rounded-xl bg-black border border-slate-800 font-mono text-xs text-emerald-400 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                {envContent}
              </pre>
              <button
                onClick={handleCopyEnv}
                className="absolute top-2 right-2 px-2.5 py-1 text-[11px] font-mono bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-md transition flex items-center space-x-1"
              >
                {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>

            <div className="flex items-center justify-between pt-2">
              <span className="text-[11px] font-mono text-slate-500">
                Logged under function: secrets_env
              </span>
              <button
                onClick={() => setEnvModalOpen(false)}
                className="px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-lg transition"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
