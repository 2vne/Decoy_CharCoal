import React, { useState, useEffect, useMemo } from 'react';
import {
  Users,
  Search,
  Filter,
  CheckCircle2,
  Building2,
  CreditCard,
  Eye,
  RefreshCw,
  X,
  FileSpreadsheet,
  AlertTriangle,
  ArrowUpDown,
  Shield,
  Layers,
} from 'lucide-react';
import { BASE_URL } from '../api/client';

export default function PortalCustomers({ basePath }) {
  const [customers, setCustomers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [planFilter, setPlanFilter] = useState('ALL');
  const [selectedCustomer, setSelectedCustomer] = useState(null);

  const fetchCustomers = async () => {
    try {
      setLoading(true);
      setError('');
      const res = await fetch(`${BASE_URL}${basePath}/customers`);
      if (!res.ok) {
        throw new Error(`Failed to load customer registry: HTTP ${res.status}`);
      }
      const data = await res.json();
      setCustomers(data.customers || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCustomers();
  }, [basePath]);

  const filteredCustomers = useMemo(() => {
    return customers.filter((c) => {
      const matchSearch =
        c.name.toLowerCase().includes(search.toLowerCase()) ||
        c.id.toLowerCase().includes(search.toLowerCase());
      const matchPlan =
        planFilter === 'ALL' || (c.plan && c.plan.toUpperCase().includes(planFilter));
      return matchSearch && matchPlan;
    });
  }, [customers, search, planFilter]);

  const plans = useMemo(() => {
    const set = new Set();
    customers.forEach((c) => {
      if (c.plan) set.add(c.plan.split('_')[0].toUpperCase());
    });
    return Array.from(set);
  }, [customers]);

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-xl font-bold text-slate-900 tracking-tight">
              Customer & Tenant Directory
            </h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-50 text-blue-700 border border-blue-200">
              {customers.length} Tenants Registered
            </span>
          </div>
          <p className="text-sm text-slate-500 mt-1">
            Manage provisioned enterprise cloud accounts, billing balances, and compute entitlements.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={fetchCustomers}
            disabled={loading}
            className="px-3 py-2 text-xs font-medium text-slate-600 bg-slate-100 hover:bg-slate-200 rounded-lg transition flex items-center space-x-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Reload Tenants</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-amber-50 border border-amber-200 text-amber-800 text-xs flex items-center space-x-2">
          <AlertTriangle className="h-4 w-4 text-amber-600 flex-shrink-0" />
          <span>Notice: {error}</span>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm flex flex-col sm:flex-row items-center justify-between gap-3">
        {/* Search */}
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search tenant name or ID..."
            className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 transition"
          />
        </div>

        {/* Plan Filter Badges */}
        <div className="flex items-center space-x-1.5 overflow-x-auto w-full sm:w-auto">
          <span className="text-xs text-slate-400 font-medium mr-1 flex items-center gap-1">
            <Filter className="w-3.5 h-3.5" /> Plan:
          </span>
          <button
            onClick={() => setPlanFilter('ALL')}
            className={`px-2.5 py-1 rounded-md text-xs font-medium transition ${
              planFilter === 'ALL'
                ? 'bg-blue-600 text-white'
                : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
            }`}
          >
            All Plans
          </button>
          {plans.map((p) => (
            <button
              key={p}
              onClick={() => setPlanFilter(p)}
              className={`px-2.5 py-1 rounded-md text-xs font-medium transition ${
                planFilter === p
                  ? 'bg-blue-600 text-white'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      {/* Customer Data Table */}
      <div className="bg-white border border-slate-200 rounded-xl shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 border-b border-slate-200 text-slate-500 font-semibold uppercase tracking-wider text-[11px]">
              <tr>
                <th className="py-3 px-4">Organization / Tenant</th>
                <th className="py-3 px-4">Tenant ID</th>
                <th className="py-3 px-4">Subscription Plan</th>
                <th className="py-3 px-4">Billing Balance</th>
                <th className="py-3 px-4">Account Status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-400">
                    <div className="flex items-center justify-center space-x-2">
                      <div className="h-4 w-4 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
                      <span>Querying customer database...</span>
                    </div>
                  </td>
                </tr>
              ) : filteredCustomers.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-400">
                    No matching enterprise customers found.
                  </td>
                </tr>
              ) : (
                filteredCustomers.map((cust) => (
                  <tr key={cust.id} className="hover:bg-slate-50/70 transition">
                    <td className="py-3 px-4">
                      <div className="flex items-center space-x-3">
                        <div className="h-8 w-8 rounded-lg bg-slate-100 text-slate-600 flex items-center justify-center font-bold text-xs uppercase border border-slate-200">
                          {cust.name.slice(0, 2)}
                        </div>
                        <div>
                          <div className="font-semibold text-slate-900">{cust.name}</div>
                          <div className="text-[11px] text-slate-400">Verified Corporate Account</div>
                        </div>
                      </div>
                    </td>

                    <td className="py-3 px-4 font-mono font-medium text-slate-700">
                      {cust.id}
                    </td>

                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded-md text-xs font-semibold bg-slate-100 text-slate-700 border border-slate-200">
                        {cust.plan || 'Standard'}
                      </span>
                    </td>

                    <td className="py-3 px-4 font-mono font-semibold text-slate-800">
                      {cust.balance || '$0.00'}
                    </td>

                    <td className="py-3 px-4">
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-emerald-50 text-emerald-700 border border-emerald-200">
                        <CheckCircle2 className="w-3 h-3" /> Active
                      </span>
                    </td>

                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => setSelectedCustomer(cust)}
                        className="px-2.5 py-1 text-xs font-medium text-blue-600 hover:text-blue-700 bg-blue-50 hover:bg-blue-100 rounded-md transition flex items-center gap-1 ml-auto"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        <span>Inspect Tenant</span>
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Customer Detail Modal */}
      {selectedCustomer && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg bg-white rounded-2xl border border-slate-200 shadow-2xl p-6 space-y-4 animate-scale-in">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <div className="flex items-center space-x-2 text-slate-900 font-bold text-base">
                <Building2 className="w-5 h-5 text-blue-600" />
                <span>Tenant Specification: {selectedCustomer.name}</span>
              </div>
              <button
                onClick={() => setSelectedCustomer(null)}
                className="text-slate-400 hover:text-slate-600"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3 p-3 rounded-xl bg-slate-50 border border-slate-200">
                <div>
                  <div className="text-slate-400 text-[11px]">Tenant Unique ID</div>
                  <div className="font-mono font-bold text-slate-800 mt-0.5">{selectedCustomer.id}</div>
                </div>
                <div>
                  <div className="text-slate-400 text-[11px]">Assigned Plan</div>
                  <div className="font-semibold text-slate-800 mt-0.5">{selectedCustomer.plan}</div>
                </div>
                <div>
                  <div className="text-slate-400 text-[11px]">Outstanding Balance</div>
                  <div className="font-mono font-bold text-emerald-600 mt-0.5">{selectedCustomer.balance}</div>
                </div>
                <div>
                  <div className="text-slate-400 text-[11px]">SLA Tier</div>
                  <div className="font-semibold text-slate-800 mt-0.5">99.99% Enterprise Support</div>
                </div>
              </div>

              {selectedCustomer.trap_tag && (
                <div className="p-3 rounded-xl bg-amber-50 border border-amber-200 text-amber-800 flex items-start space-x-2">
                  <Shield className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />
                  <div>
                    <div className="font-semibold text-amber-900">Synthetic Decoy Canary Tag</div>
                    <div className="text-[11px] font-mono mt-0.5 text-amber-700">
                      {selectedCustomer.trap_tag}
                    </div>
                  </div>
                </div>
              )}

              <div className="text-slate-500 text-[11px]">
                Provisioned within enterprise partition US-East-1A. Encrypted under customer-managed HSM key.
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setSelectedCustomer(null)}
                className="px-4 py-2 text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg transition"
              >
                Close Specification
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

