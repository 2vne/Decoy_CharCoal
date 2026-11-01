import React, { useState } from 'react';
import {
  CreditCard,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Receipt,
  ArrowRight,
  RefreshCw,
  Lock,
  Download,
  X,
  Building2,
  DollarSign,
} from 'lucide-react';
import { BASE_URL } from '../api/client';

export default function PortalBilling({ basePath }) {
  const [amount, setAmount] = useState(150.0);
  const [customerId, setCustomerId] = useState('canary_901');
  const [token, setToken] = useState('tok_enterprise_canary_8819');
  const [loading, setLoading] = useState(false);
  const [receipt, setReceipt] = useState(null);
  const [error, setError] = useState('');

  const handleProcessCharge = async (e) => {
    e.preventDefault();
    try {
      setLoading(true);
      setError('');
      setReceipt(null);

      const res = await fetch(`${BASE_URL}${basePath}/checkout/charge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          customer_id: customerId,
          amount: parseFloat(amount),
          currency: 'USD',
          token,
        }),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(data.detail || `Transaction authorization failed: HTTP ${res.status}`);
      }

      setReceipt(data);
    } catch (err) {
      setError(err.message || 'Payment processor returned verification error.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-xl font-bold text-slate-900 tracking-tight">
              Enterprise Subscription & Billing Management
            </h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
              Active Tier
            </span>
          </div>
          <p className="text-sm text-slate-500 mt-1">
            Review compute plan entitlements, assigned payment methods, and execute test account top-ups.
          </p>
        </div>
      </div>

      {/* Safety Banner */}
      <div className="p-4 rounded-xl bg-blue-50 border border-blue-200 text-blue-900 text-xs flex items-start space-x-3">
        <ShieldCheck className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
        <div>
          <div className="font-semibold text-blue-950">Simulated Financial Processing Sandbox</div>
          <div className="text-blue-700 mt-0.5">
            This checkout terminal operates in a secure testing mode. No real credit card, banking, or financial transactions are ever conducted. All interactions are evaluated by SENTINEL's telemetry engine.
          </div>
        </div>
      </div>

      {/* Top 2 Columns: Plan Overview & Payment Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Current Plan Card */}
        <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Current Plan</span>
            <span className="px-2 py-0.5 rounded text-xs font-bold bg-blue-100 text-blue-700">Enterprise Cloud</span>
          </div>
          <div>
            <div className="text-3xl font-black text-slate-900 tracking-tight">$4,200.00 <span className="text-sm font-normal text-slate-400">/ month</span></div>
            <p className="text-xs text-slate-500 mt-1">Includes unlimited gateway evaluations, 10 cluster nodes, and 24/7 SRE response.</p>
          </div>
          <div className="pt-2 border-t border-slate-100 space-y-2 text-xs text-slate-600">
            <div className="flex justify-between">
              <span>Billing Cycle:</span>
              <span className="font-medium text-slate-800">Monthly auto-renewal</span>
            </div>
            <div className="flex justify-between">
              <span>Next Invoice:</span>
              <span className="font-medium text-slate-800">November 15, 2026</span>
            </div>
          </div>
        </div>

        {/* Payment Method Card */}
        <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Primary Card</span>
            <CreditCard className="w-4 h-4 text-slate-400" />
          </div>

          <div className="p-4 rounded-xl bg-gradient-to-r from-slate-900 to-slate-800 text-white shadow-md space-y-4">
            <div className="flex justify-between items-center text-xs text-slate-400">
              <span>Corporate Fleet Card</span>
              <span className="font-mono font-bold text-white text-sm">VISA</span>
            </div>
            <div className="font-mono text-base tracking-widest text-slate-100">
              •••• •••• •••• 4242
            </div>
            <div className="flex justify-between items-end text-[11px] text-slate-300">
              <div>
                <div className="text-[9px] uppercase text-slate-400">Cardholder</div>
                <div>SENTINEL HOLDINGS</div>
              </div>
              <div>
                <div className="text-[9px] uppercase text-slate-400">Expires</div>
                <div>12/28</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Simulated Top-up / Payment Form */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-slate-100 pb-3">
          <div className="flex items-center space-x-2">
            <CreditCard className="w-5 h-5 text-emerald-600" />
            <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
              Authorize Account Top-Up / Add-on Compute
            </h2>
          </div>
          <span className="text-xs font-mono text-slate-400">Payment Gateway Target: payment_gateway</span>
        </div>

        {error && (
          <div className="p-3 rounded-lg bg-red-50 border border-red-200 text-red-800 text-xs flex items-center space-x-2">
            <AlertTriangle className="h-4 w-4 text-red-600 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleProcessCharge} className="space-y-4 text-xs">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-slate-600 font-medium mb-1">Target Customer Account:</label>
              <select
                value={customerId}
                onChange={(e) => setCustomerId(e.target.value)}
                className="w-full p-2 bg-slate-50 border border-slate-200 rounded-lg text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono"
              >
                <option value="canary_901">canary_901 (Shadow Corp Decoy)</option>
                <option value="canary_902">canary_902 (Ghost Holdings Ltd)</option>
                <option value="cust_101">cust_101 (Acme Cyber Dynamics)</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-600 font-medium mb-1">Charge Amount ($ USD):</label>
              <input
                type="number"
                step="0.01"
                min="1"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                className="w-full p-2 bg-slate-50 border border-slate-200 rounded-lg text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono"
                required
              />
            </div>

            <div>
              <label className="block text-slate-600 font-medium mb-1">Payment Token Identifier:</label>
              <input
                type="text"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                className="w-full p-2 bg-slate-50 border border-slate-200 rounded-lg text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-xs"
                required
              />
            </div>
          </div>

          <div className="pt-2 flex justify-end">
            <button
              type="submit"
              disabled={loading}
              className="px-5 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded-lg shadow-sm transition flex items-center space-x-2 cursor-pointer disabled:opacity-50"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Authorizing Transaction...</span>
                </>
              ) : (
                <>
                  <CreditCard className="w-4 h-4" />
                  <span>Submit Payment Authorization (${parseFloat(amount || 0).toFixed(2)})</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Payment Receipt Modal */}
      {receipt && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-sm p-4">
          <div className="w-full max-w-md bg-white rounded-2xl border border-slate-200 shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <div className="flex items-center space-x-2 text-slate-900 font-bold text-base">
                <CheckCircle2 className="w-5 h-5 text-emerald-500" />
                <span>Transaction Succeeded</span>
              </div>
              <button
                onClick={() => setReceipt(null)}
                className="text-slate-400 hover:text-slate-600"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                <div className="flex justify-between items-center text-slate-500">
                  <span>Charge Identifier:</span>
                  <span className="font-mono font-bold text-slate-900">{receipt.charge_id}</span>
                </div>
                <div className="flex justify-between items-center text-slate-500">
                  <span>Authorized Amount:</span>
                  <span className="font-mono font-bold text-emerald-600 text-sm">
                    ${parseFloat(receipt.amount || 0).toFixed(2)} {receipt.currency}
                  </span>
                </div>
                <div className="flex justify-between items-center text-slate-500">
                  <span>Processor Status:</span>
                  <span className="font-bold text-emerald-600 uppercase">{receipt.status}</span>
                </div>

                {receipt.decoy_watermark && (
                  <div className="pt-2 border-t border-slate-200 flex justify-between items-center text-amber-700 font-mono text-[11px]">
                    <span>Decoy Watermark:</span>
                    <span className="font-bold">{receipt.decoy_watermark}</span>
                  </div>
                )}
              </div>

              <div className="text-[11px] text-slate-400 text-center">
                Telemetry recorded under payment_gateway function. Receipt logged in audit trail.
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setReceipt(null)}
                className="w-full py-2 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-lg transition"
              >
                Close Receipt
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

