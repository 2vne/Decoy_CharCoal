import React, { useState, useEffect } from 'react';
import {
  Shield,
  Lock,
  Mail,
  Eye,
  EyeOff,
  ArrowRight,
  CheckCircle2,
  AlertCircle,
  KeyRound,
  ExternalLink,
} from 'lucide-react';
import { BASE_URL, api } from '../api/client';

export default function PortalLogin({
  onLoginSuccess,
  onForgotPassword,
  basePath,
  setBasePath,
}) {
  const [email, setEmail] = useState('admin@sentinel-corp.internal');
  const [password, setPassword] = useState('AdminSecure2026!');
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [backendStatus, setBackendStatus] = useState('checking');

  useEffect(() => {
    let unmounted = false;
    const probe = async () => {
      const res = await api.checkHealth();
      if (!unmounted) {
        setBackendStatus(res.ok ? 'connected' : 'disconnected');
      }
    };
    probe();
    const interval = setInterval(probe, 5000);
    return () => {
      unmounted = true;
      clearInterval(interval);
    };
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!email || !password) {
      setError('Please provide both your corporate email and password.');
      return;
    }

    try {
      setLoading(true);
      setError('');

      const res = await fetch(`${BASE_URL}${basePath}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(data.detail || `Authentication failed with status ${res.status}`);
      }

      // Successful primary authentication
      onLoginSuccess({
        email,
        sessionToken: data.session_token || `sess_${Date.now()}`,
        requiresOtp: Boolean(data.requires_otp),
        message: data.message || 'Primary credentials verified.',
      });
    } catch (err) {
      setError(err.message || 'Failed to authenticate with enterprise identity server.');
    } finally {
      setLoading(false);
    }
  };

  const setPresetCredentials = (presetEmail, presetPw) => {
    setEmail(presetEmail);
    setPassword(presetPw);
    setError('');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-950 flex flex-col justify-center py-12 sm:px-6 lg:px-8 text-slate-100 font-sans">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        {/* Brand Logo & Header */}
        <div className="flex justify-center items-center space-x-3 mb-2">
          <div className="h-12 w-12 rounded-xl bg-blue-600 flex items-center justify-center shadow-lg shadow-blue-500/30 ring-1 ring-blue-400">
            <Shield className="h-7 w-7 text-white" />
          </div>
          <div className="text-left">
            <span className="text-2xl font-black tracking-tight text-white block">
              SENTINEL<span className="text-blue-400 font-normal">PORTAL</span>
            </span>
            <span className="text-[11px] font-mono tracking-wider text-slate-400 uppercase block -mt-1">
              Enterprise Cloud & Identity
            </span>
          </div>
        </div>

        <h2 className="mt-4 text-center text-xl font-semibold tracking-tight text-slate-200">
          Sign in to your enterprise workspace
        </h2>
        <p className="mt-1 text-center text-xs text-slate-400">
          Managed multi-tenant infrastructure & cloud security gateway
        </p>

        {/* Environment / Routing Mode Selector */}
        <div className="mt-3 flex items-center justify-center gap-2 text-xs">
          <span className="text-slate-400 text-[11px]">Portal Route:</span>
          <div className="inline-flex rounded-lg bg-slate-950/80 p-0.5 border border-slate-800">
            <button
              type="button"
              onClick={() => setBasePath('/demo/decoy')}
              className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition ${
                basePath === '/demo/decoy'
                  ? 'bg-amber-600/90 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Decoy Sandbox
            </button>
            <button
              type="button"
              onClick={() => setBasePath('/demo/real')}
              className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition ${
                basePath === '/demo/real'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Production Real
            </button>
          </div>
        </div>

        {/* Backend Connectivity Status Pill */}
        <div className="mt-2.5 flex items-center justify-center">
          <div
            className={`inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-[11px] font-mono border transition shadow-sm ${
              backendStatus === 'connected'
                ? 'bg-emerald-950/70 border-emerald-500/40 text-emerald-300'
                : backendStatus === 'checking'
                ? 'bg-slate-800 border-slate-700 text-slate-300'
                : 'bg-rose-950/80 border-rose-500/50 text-rose-300 animate-pulse'
            }`}
          >
            <span
              className={`h-2 w-2 rounded-full ${
                backendStatus === 'connected'
                  ? 'bg-emerald-400'
                  : backendStatus === 'checking'
                  ? 'bg-amber-400 animate-ping'
                  : 'bg-rose-500'
              }`}
            />
            <span>
              {backendStatus === 'connected'
                ? 'Backend Connected'
                : backendStatus === 'checking'
                ? 'Connecting to Backend...'
                : 'Backend Disconnected (Retrying...)'}
            </span>
          </div>
        </div>
      </div>

      <div className="mt-6 sm:mx-auto sm:w-full sm:max-w-md px-4 sm:px-0">
        <div className="bg-slate-900/90 py-8 px-6 shadow-2xl rounded-2xl border border-slate-700/80 backdrop-blur-xl sm:px-10">
          {error && (
            <div className="mb-5 rounded-lg bg-red-950/70 border border-red-500/60 p-3 text-xs text-red-200 flex items-start space-x-2 animate-fade-in">
              <AlertCircle className="h-4 w-4 text-red-400 flex-shrink-0 mt-0.5" />
              <div className="flex-1">{error}</div>
            </div>
          )}

          <form className="space-y-4" onSubmit={handleSubmit}>
            {/* Email Field */}
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Corporate Email Address
              </label>
              <div className="relative rounded-lg shadow-sm">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                  <Mail className="h-4 w-4" />
                </div>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@sentinel.local"
                  required
                  className="block w-full pl-9 pr-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition"
                />
              </div>
            </div>

            {/* Password Field */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="block text-xs font-medium text-slate-300">
                  Password
                </label>
                <button
                  type="button"
                  onClick={onForgotPassword}
                  className="text-xs text-blue-400 hover:text-blue-300 transition"
                >
                  Forgot password?
                </button>
              </div>
              <div className="relative rounded-lg shadow-sm">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                  <Lock className="h-4 w-4" />
                </div>
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  required
                  className="block w-full pl-9 pr-10 py-2 text-sm bg-slate-950 border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-400 hover:text-slate-200"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            {/* Remember Me */}
            <div className="flex items-center justify-between pt-1">
              <label className="flex items-center space-x-2 text-xs text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-950 text-blue-600 focus:ring-blue-500 h-4 w-4"
                />
                <span>Remember this terminal</span>
              </label>
              <span className="text-[11px] text-slate-400 flex items-center gap-1 font-mono">
                <KeyRound className="w-3 h-3 text-emerald-400" /> MFA Enforced
              </span>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={loading}
              className="w-full mt-2 flex justify-center items-center py-2.5 px-4 border border-transparent rounded-lg shadow-sm text-sm font-semibold text-white bg-blue-600 hover:bg-blue-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 transition cursor-pointer"
            >
              {loading ? (
                <div className="flex items-center space-x-2">
                  <div className="h-4 w-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Authenticating Identity...</span>
                </div>
              ) : (
                <div className="flex items-center space-x-2">
                  <span>Sign In to Workspace</span>
                  <ArrowRight className="h-4 w-4" />
                </div>
              )}
            </button>
          </form>

          {/* Quick Credential Presets for Demonstrations */}
          <div className="mt-6 pt-5 border-t border-slate-800">
            <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-2 flex items-center justify-between">
              <span>Quick Test Identities</span>
              <span className="text-slate-400 text-[10px]">Click to prefill</span>
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <button
                type="button"
                onClick={() => {
                  setBasePath('/demo/decoy');
                  setPresetCredentials('target@evil-corp.com', 'StolenPassword123!');
                }}
                className="p-2 rounded bg-slate-950 border border-slate-800 hover:border-amber-500/60 text-left transition"
              >
                <div className="font-semibold text-amber-300">Decoy Attacker</div>
                <div className="text-[10px] text-slate-400 truncate">target@evil-corp.com</div>
              </button>

              <button
                type="button"
                onClick={() => {
                  setBasePath('/demo/real');
                  setPresetCredentials('analyst@sentinel.local', 'Password123!');
                }}
                className="p-2 rounded bg-slate-950 border border-slate-800 hover:border-blue-500/60 text-left transition"
              >
                <div className="font-semibold text-blue-300">Real Analyst</div>
                <div className="text-[10px] text-slate-400 truncate">analyst@sentinel.local</div>
              </button>
            </div>
          </div>
        </div>

        {/* Security & Compliance Footer Badges */}
        <div className="mt-6 flex items-center justify-center space-x-4 text-[11px] text-slate-400 font-mono">
          <span className="flex items-center gap-1">
            <CheckCircle2 className="h-3 w-3 text-emerald-400" /> TLS 1.3 / 256-bit AES
          </span>
          <span>•</span>
          <span>SOC-2 Type II</span>
          <span>•</span>
          <span>FIPS 140-3</span>
        </div>
      </div>
    </div>
  );
}

