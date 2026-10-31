import React, { useState } from 'react';
import {
  ShieldAlert,
  Search,
  Lock,
  Unlock,
  Loader2,
  ChevronRight,
  ExternalLink,
  MapPin,
  Share2,
} from 'lucide-react';
import { useSoc } from '../context/SocContext';

export default function AttackersPage() {
  const { attackers, setSelectedAttackerId, blockAttacker, unblockAttacker } = useSoc();
  const [search, setSearch] = useState('');
  const [bandFilter, setBandFilter] = useState('all');
  const [loadingId, setLoadingId] = useState(null); // attacker id currently being blocked/unblocked

  const filtered = attackers.filter((a) => {
    if (bandFilter !== 'all' && a.risk_band !== bandFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        a.ip.toLowerCase().includes(q) ||
        (a.intent && a.intent.toLowerCase().includes(q)) ||
        (a.fingerprint && a.fingerprint.toLowerCase().includes(q))
      );
    }
    return true;
  });

  const getBandBadge = (band) => {
    switch (band) {
      case 'critical':
        return 'bg-red-950 text-red-400 border-red-500/50';
      case 'high':
        return 'bg-orange-950 text-orange-400 border-orange-500/50';
      case 'medium':
        return 'bg-yellow-950 text-yellow-400 border-yellow-500/50';
      default:
        return 'bg-emerald-950 text-emerald-400 border-emerald-500/50';
    }
  };

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-bold font-mono text-white tracking-wider flex items-center space-x-2">
          <span>ATTACKER PROFILES</span>
          <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 border border-cyan-500/30 text-cyan-300 font-bold">
            {attackers.length} PROFILES
          </span>
        </h1>
        <p className="text-xs font-mono text-soc-muted mt-0.5">
          Per-IP behavioral dossiers, persistent fingerprints, and containment status
        </p>
      </div>

      {/* Search & Band Filters */}
      <div className="p-3 rounded border border-soc-border bg-soc-card flex flex-wrap items-center gap-3 text-xs font-mono">
        <div className="flex-1 min-w-[220px] relative">
          <Search className="h-3.5 w-3.5 text-soc-muted absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search IP, fingerprint, or intent..."
            className="w-full bg-soc-surface border border-soc-border rounded pl-8 pr-3 py-1.5 text-white placeholder-soc-muted focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex items-center space-x-1.5">
          {['all', 'critical', 'high', 'medium', 'low'].map((b) => (
            <button
              key={b}
              onClick={() => setBandFilter(b)}
              className={`px-2.5 py-1 rounded uppercase font-medium transition ${
                bandFilter === b
                  ? 'bg-cyan-950 border border-cyan-400 text-cyan-200 shadow-[0_0_8px_rgba(0,240,255,0.3)]'
                  : 'bg-soc-surface border border-soc-border text-soc-muted hover:text-white'
              }`}
            >
              {b}
            </button>
          ))}
        </div>
      </div>

      {/* Attackers Table */}
      <div className="rounded border border-soc-border bg-soc-surface overflow-hidden shadow-2xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-soc-card/90 text-soc-muted border-b border-soc-border">
              <tr>
                <th className="py-3 px-4">ATTACKER IP</th>
                <th className="py-3 px-4">RISK SCORE</th>
                <th className="py-3 px-4">LOCATION</th>
                <th className="py-3 px-4">HONEYPOTS</th>
                <th className="py-3 px-4">INFERRED INTENT</th>
                <th className="py-3 px-4">STATUS</th>
                <th className="py-3 px-4 text-right">ACTIONS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border/60">
              {filtered.length > 0 ? (
                filtered.map((atk) => (
                  <tr
                    key={atk.id}
                    onClick={() => setSelectedAttackerId(atk.id)}
                    className="hover:bg-soc-card/60 transition cursor-pointer group"
                  >
                  <td className="py-3 px-4">
                    <div className="flex items-center space-x-2">
                      <span className="font-bold text-white text-sm group-hover:text-cyan-300 transition">
                        {atk.ip}
                      </span>
                      {atk.is_repeat && (
                        <span className="px-1.5 py-0.2 rounded text-[9px] bg-cyan-950 border border-cyan-500/40 text-cyan-300 font-bold">
                          REPEAT
                        </span>
                      )}
                    </div>
                    <div className="text-[10px] text-soc-muted mt-0.5 truncate max-w-xs">
                      FP: {atk.fingerprint ? `${atk.fingerprint.slice(0, 16)}...` : 'N/A'}
                    </div>
                  </td>

                  <td className="py-3 px-4">
                    <span
                      className={`inline-block px-2.5 py-0.5 rounded text-[11px] font-bold uppercase border ${getBandBadge(
                        atk.risk_band
                      )}`}
                    >
                      {atk.risk_score?.toFixed(0)} ({atk.risk_band})
                    </span>
                  </td>

                  <td className="py-3 px-4 text-soc-muted">
                    {atk.geo?.country ? (
                      <span className="flex items-center space-x-1">
                        <MapPin className="h-3 w-3 text-soc-muted" />
                        <span>{atk.geo.city || atk.geo.country}, {atk.geo.country}</span>
                      </span>
                    ) : (
                      'Unknown'
                    )}
                  </td>

                  <td className="py-3 px-4 uppercase text-soc-muted">
                    {atk.honeypots_touched?.join(', ') || 'N/A'}
                  </td>

                  <td className="py-3 px-4">
                    <span className="text-white capitalize font-medium">{atk.intent || 'reconnaissance'}</span>
                  </td>

                  <td className="py-3 px-4">
                    {atk.status === 'blocked' ? (
                      <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-red-950 text-red-300 text-[10px] font-bold border border-red-500/40">
                        <Lock className="h-2.5 w-2.5" />
                        <span>BLOCKED</span>
                      </span>
                    ) : atk.status === 'watchlist' ? (
                      <span className="px-2 py-0.5 rounded bg-yellow-950 text-yellow-300 text-[10px] font-bold border border-yellow-500/40">
                        WATCHLIST
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded bg-soc-card text-soc-muted text-[10px] border border-soc-border">
                        ACTIVE
                      </span>
                    )}
                  </td>

                  <td className="py-3 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                    <div className="flex items-center justify-end space-x-2">
                      {atk.status === 'blocked' ? (
                        <button
                          disabled={loadingId === atk.id}
                          onClick={async () => {
                            setLoadingId(atk.id);
                            try {
                              await unblockAttacker(atk.id, atk.ip);
                            } finally {
                              setLoadingId(null);
                            }
                          }}
                          className="px-2.5 py-1 rounded bg-emerald-950 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-900 transition text-[11px] font-medium flex items-center space-x-1 disabled:opacity-60"
                        >
                          {loadingId === atk.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <Unlock className="h-3 w-3" />}
                          <span>UNBLOCK</span>
                        </button>
                      ) : (
                        <button
                          disabled={loadingId === atk.id}
                          onClick={async () => {
                            setLoadingId(atk.id);
                            try {
                              await blockAttacker(atk.id, atk.ip);
                            } finally {
                              setLoadingId(null);
                            }
                          }}
                          className="px-2.5 py-1 rounded bg-red-950 border border-red-500/40 text-red-300 hover:bg-red-900 transition text-[11px] font-medium flex items-center space-x-1 disabled:opacity-60"
                        >
                          {loadingId === atk.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <Lock className="h-3 w-3" />}
                          <span>BLOCK</span>
                        </button>
                      )}
                      <button
                        onClick={() => setSelectedAttackerId(atk.id)}
                        className="p-1 rounded bg-soc-card border border-soc-border text-soc-muted hover:text-white"
                        title="Open dossier"
                      >
                        <ChevronRight className="h-4 w-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))
              ) : (
                <tr>
                  <td colSpan={7} className="text-center py-12 text-soc-muted">
                    No matching attacker profiles captured.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

