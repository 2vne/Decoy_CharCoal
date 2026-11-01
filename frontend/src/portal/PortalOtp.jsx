import React, { useState, useEffect, useRef } from 'react';
import {
  ShieldCheck,
  KeyRound,
  ArrowRight,
  ArrowLeft,
  AlertCircle,
  RefreshCw,
  Clock,
  CheckCircle2,
} from 'lucide-react';

export default function PortalOtp({
  email,
  onVerifySuccess,
  onBackToLogin,
  basePath,
}) {
  const [otp, setOtp] = useState(['', '', '', '', '', '']);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [timer, setTimer] = useState(59);
  const [resending, setResending] = useState(false);
  const inputRefs = useRef([]);

  useEffect(() => {
    // Focus first input automatically
    if (inputRefs.current[0]) {
      inputRefs.current[0].focus();
    }
  }, []);

  useEffect(() => {
    if (timer > 0) {
      const interval = setInterval(() => setTimer((t) => t - 1), 1000);
      return () => clearInterval(interval);
    }
  }, [timer]);

  const handleOtpChange = (index, value) => {
    if (!/^\d*$/.test(value)) return;

    const newOtp = [...otp];
    newOtp[index] = value.slice(-1);
    setOtp(newOtp);

    // Auto-advance cursor
    if (value && index < 5 && inputRefs.current[index + 1]) {
      inputRefs.current[index + 1].focus();
    }
  };

  const handleKeyDown = (index, e) => {
    if (e.key === 'Backspace' && !otp[index] && index > 0 && inputRefs.current[index - 1]) {
      inputRefs.current[index - 1].focus();
    }
  };

  const handlePaste = (e) => {
    e.preventDefault();
    const pasted = e.clipboardData.getData('text').trim();
    if (/^\d{6}$/.test(pasted)) {
      const digits = pasted.split('');
      setOtp(digits);
      if (inputRefs.current[5]) {
        inputRefs.current[5].focus();
      }
    }
  };

  const handleVerify = async (e) => {
    if (e) e.preventDefault();
    const fullCode = otp.join('');
    if (fullCode.length !== 6) {
      setError('Please enter all 6 digits of your authorization challenge.');
      return;
    }

    try {
      setLoading(true);
      setError('');

      const res = await fetch(`${basePath}/auth/otp/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, otp_code: fullCode }),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(data.detail || `OTP challenge failed with status ${res.status}`);
      }

      onVerifySuccess({
        email,
        role: data.role || 'operator',
        user: data.user || email.split('@')[0],
        appScope: data.app_scope || 'cloud_workspace',
      });
    } catch (err) {
      setError(err.message || 'Invalid authorization code. Verification failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleResend = () => {
    if (timer > 0) return;
    setResending(true);
    setTimeout(() => {
      setTimer(59);
      setResending(false);
      setError('');
    }, 700);
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
              SENTINEL<span className="text-blue-400 font-normal">PORTAL</span>
            </span>
            <span className="text-[11px] font-mono tracking-wider text-slate-400 uppercase block -mt-1">
              Two-Factor Authentication
            </span>
          </div>
        </div>

        <h2 className="mt-4 text-center text-xl font-semibold tracking-tight text-slate-200">
          Enter Verification Code
        </h2>
        <p className="mt-1 text-center text-xs text-slate-400">
          A 6-digit challenge has been generated for{' '}
          <span className="text-slate-200 font-mono font-medium">{email}</span>
        </p>
      </div>

      <div className="mt-6 sm:mx-auto sm:w-full sm:max-w-md px-4 sm:px-0">
        <div className="bg-slate-900/90 py-8 px-6 shadow-2xl rounded-2xl border border-slate-700/80 backdrop-blur-xl sm:px-10">
          {error && (
            <div className="mb-5 rounded-lg bg-red-950/70 border border-red-500/60 p-3 text-xs text-red-200 flex items-start space-x-2 animate-fade-in">
              <AlertCircle className="h-4 w-4 text-red-400 flex-shrink-0 mt-0.5" />
              <div className="flex-1">{error}</div>
            </div>
          )}

          <form onSubmit={handleVerify} className="space-y-6">
            {/* 6 Digit Segmented Inputs */}
            <div>
              <label className="block text-center text-xs font-medium text-slate-300 mb-3">
                Security Token (6 Digits)
              </label>
              <div className="flex justify-between gap-2" onPaste={handlePaste}>
                {otp.map((digit, idx) => (
                  <input
                    key={idx}
                    ref={(el) => (inputRefs.current[idx] = el)}
                    type="text"
                    inputMode="numeric"
                    maxLength={1}
                    value={digit}
                    onChange={(e) => handleOtpChange(idx, e.target.value)}
                    onKeyDown={(e) => handleKeyDown(idx, e)}
                    className="w-12 h-13 text-center text-xl font-mono font-bold bg-slate-950 border border-slate-700 rounded-xl text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition shadow-inner"
                  />
                ))}
              </div>
            </div>

            {/* Quick prefill helper for demo */}
            <div className="text-center text-[11px] text-slate-400">
              <span>Demo secret token: </span>
              <button
                type="button"
                onClick={() => setOtp(['7', '8', '9', '1', '2', '3'])}
                className="text-blue-400 hover:text-blue-300 font-mono underline"
              >
                789123
              </button>
              <span> (or enter any code for decoy trap)</span>
            </div>

            {/* Verification Button */}
            <button
              type="submit"
              disabled={loading}
              className="w-full flex justify-center items-center py-2.5 px-4 border border-transparent rounded-lg shadow-sm text-sm font-semibold text-white bg-blue-600 hover:bg-blue-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 transition cursor-pointer"
            >
              {loading ? (
                <div className="flex items-center space-x-2">
                  <div className="h-4 w-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Validating Security Key...</span>
                </div>
              ) : (
                <div className="flex items-center space-x-2">
                  <span>Verify & Grant Access</span>
                  <ArrowRight className="h-4 w-4" />
                </div>
              )}
            </button>
          </form>

          {/* Resend and Return Actions */}
          <div className="mt-6 pt-5 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
            <button
              type="button"
              onClick={onBackToLogin}
              className="flex items-center gap-1 text-slate-400 hover:text-slate-200 transition"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to Login</span>
            </button>

            <button
              type="button"
              onClick={handleResend}
              disabled={timer > 0 || resending}
              className="flex items-center gap-1 text-blue-400 hover:text-blue-300 disabled:opacity-40 transition"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${resending ? 'animate-spin' : ''}`} />
              <span>{timer > 0 ? `Resend code (${timer}s)` : 'Resend code'}</span>
            </button>
          </div>
        </div>

        {/* Security Trust Note */}
        <div className="mt-4 text-center text-[11px] text-slate-500">
          Hardware Security Module (HSM) session key rotation active.
        </div>
      </div>
    </div>
  );
}
