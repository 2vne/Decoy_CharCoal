import React, { useState } from 'react';
import {
  Shield,
  Mail,
  ArrowRight,
  ArrowLeft,
  CheckCircle2,
  AlertCircle,
  KeyRound,
} from 'lucide-react';
import { BASE_URL } from '../api/client';

export default function PortalPasswordReset({ onBackToLogin, basePath }) {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const handleReset = async (e) => {
    e.preventDefault();
    if (!email) {
      setError('Please provide your corporate email address.');
      return;
    }

    try {
      setLoading(true);
      setError('');
      setMessage('');

      const res = await fetch(`${BASE_URL}${basePath}/auth/password/reset`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(data.detail || `Recovery request failed with status ${res.status}`);
      }

      setMessage(
        data.message ||
          `If an account matching "${email}" exists, a time-limited password recovery link has been dispatched.`
      );
    } catch (err) {
      setError(err.message || 'Unable to queue recovery token. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-950 flex flex-col justify-center py-12 sm:px-6 lg:px-8 text-slate-100 font-sans">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <div className="flex justify-center items-center space-x-3 mb-2">
          <div className="h-12 w-12 rounded-xl bg-blue-600 flex items-center justify-center shadow-lg shadow-blue-500/30 ring-1 ring-blue-400">
            <KeyRound className="h-7 w-7 text-white" />
          </div>
          <div className="text-left">
            <span className="text-2xl font-black tracking-tight text-white block">
              MIRAGE<span className="text-blue-400 font-normal">PORTAL</span>
            </span>
            <span className="text-[11px] font-mono tracking-wider text-slate-400 uppercase block -mt-1">
              Account Access Recovery
            </span>
          </div>
        </div>

        <h2 className="mt-4 text-center text-xl font-semibold tracking-tight text-slate-200">
          Reset Your Access Credential
        </h2>
        <p className="mt-1 text-center text-xs text-slate-400">
          Provide your enterprise email to receive recovery instructions.
        </p>
      </div>

      <div className="mt-6 sm:mx-auto sm:w-full sm:max-w-md px-4 sm:px-0">
        <div className="bg-slate-900/90 py-8 px-6 shadow-2xl rounded-2xl border border-slate-700/80 backdrop-blur-xl sm:px-10">
          {error && (
            <div className="mb-5 rounded-lg bg-red-950/70 border border-red-500/60 p-3 text-xs text-red-200 flex items-start space-x-2">
              <AlertCircle className="h-4 w-4 text-red-400 flex-shrink-0 mt-0.5" />
              <div className="flex-1">{error}</div>
            </div>
          )}

          {message ? (
            <div className="space-y-4">
              <div className="rounded-xl bg-emerald-950/70 border border-emerald-500/60 p-4 text-xs text-emerald-200 space-y-2">
                <div className="flex items-center space-x-2 font-semibold text-emerald-300">
                  <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                  <span>Recovery Instructions Dispatched</span>
                </div>
                <p className="leading-relaxed">{message}</p>
              </div>

              <button
                type="button"
                onClick={onBackToLogin}
                className="w-full flex justify-center items-center py-2.5 px-4 border border-transparent rounded-lg shadow-sm text-sm font-semibold text-white bg-blue-600 hover:bg-blue-500 transition"
              >
                <span>Return to Sign In</span>
              </button>
            </div>
          ) : (
            <form onSubmit={handleReset} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Registered Corporate Email
                </label>
                <div className="relative rounded-lg shadow-sm">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                    <Mail className="h-4 w-4" />
                  </div>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="user@enterprise.corp"
                    required
                    className="block w-full pl-9 pr-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full flex justify-center items-center py-2.5 px-4 border border-transparent rounded-lg shadow-sm text-sm font-semibold text-white bg-blue-600 hover:bg-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50 transition"
              >
                {loading ? (
                  <div className="flex items-center space-x-2">
                    <div className="h-4 w-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    <span>Validating Address...</span>
                  </div>
                ) : (
                  <div className="flex items-center space-x-2">
                    <span>Dispatch Recovery Link</span>
                    <ArrowRight className="h-4 w-4" />
                  </div>
                )}
              </button>

              <div className="pt-3 text-center">
                <button
                  type="button"
                  onClick={onBackToLogin}
                  className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition"
                >
                  <ArrowLeft className="w-3.5 h-3.5" />
                  <span>Back to Sign In</span>
                </button>
              </div>
            </form>
          )}
        </div>

        <div className="mt-4 text-center text-[11px] text-slate-500">
          Security Note: Timing-safe response policy prevents corporate address enumeration.
        </div>
      </div>
    </div>
  );
}

