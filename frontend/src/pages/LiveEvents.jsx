import React, { useState, useMemo } from 'react';
import {
  Radio,
  Search,
  Pause,
  Play,
  Filter,
  ChevronDown,
  ChevronRight,
  Code,
  ShieldAlert,
} from 'lucide-react';
import { useSoc } from '../context/SocContext';

export default function LiveEvents() {
  const { events, setSelectedAttackerId, attackers, isEventsPaused, setIsEventsPaused } = useSoc();

  // Use context-level pause so WS events stop accumulating when paused
  const isPaused = isEventsPaused;
  const setIsPaused = setIsEventsPaused;
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedHoneypot, setSelectedHoneypot] = useState('all');
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [expandedRowId, setExpandedRowId] = useState(null);
  const [viewMode, setViewMode] = useState({}); // eventId -> 'normalised' | 'raw'

  // Map IP to Attacker ID
  const ipToIdMap = useMemo(() => {
    const map = {};
    attackers.forEach((a) => {
      map[a.ip] = a.id;
    });
    return map;
  }, [attackers]);

  // Filtered event stream
  const filteredEvents = useMemo(() => {
    return events.filter((ev) => {
      if (selectedHoneypot !== 'all' && ev.honeypot !== selectedHoneypot) return false;
      if (selectedSeverity !== 'all') {
        const band = ev.risk_band || 'low';
        if (band !== selectedSeverity) return false;
      }
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        const ipMatch = ev.src_ip?.toLowerCase().includes(term);
        const cmdMatch = ev.command?.toLowerCase().includes(term);
        const typeMatch = ev.event_type?.toLowerCase().includes(term);
        if (!ipMatch && !cmdMatch && !typeMatch) return false;
      }
      return true;
    });
  }, [events, selectedHoneypot, selectedSeverity, searchTerm]);

  const toggleRow = (id) => {
    setExpandedRowId((prev) => (prev === id ? null : id));
  };

  const getSeverityBadge = (band) => {
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
      {/* Header and Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono text-white tracking-wider flex items-center space-x-2">
            <span>LIVE TELEMETRY CONSOLE</span>
            {!isPaused && (
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyber-blue"></span>
              </span>
            )}
          </h1>
          <p className="text-xs font-mono text-soc-muted mt-0.5">
            Real-time honeypot ingestion and automated packet normalization
          </p>
        </div>

        {/* Action button */}
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setIsPaused(!isPaused)}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded font-mono text-xs font-bold transition border ${isPaused
                ? 'bg-amber-950 border-amber-500 text-amber-300'
                : 'bg-soc-card border-soc-border text-soc-muted hover:text-white hover:border-cyan-500'
              }`}
          >
            {isPaused ? <Play className="h-3.5 w-3.5 fill-current" /> : <Pause className="h-3.5 w-3.5 fill-current" />}
            <span>{isPaused ? 'RESUME STREAM' : 'PAUSE STREAM'}</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-3 rounded border border-soc-border bg-soc-card flex flex-wrap items-center gap-3 text-xs font-mono">
        {/* Search */}
        <div className="flex-1 min-w-[200px] relative">
          <Search className="h-3.5 w-3.5 text-soc-muted absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search IP, command, or event type..."
            className="w-full bg-soc-surface border border-soc-border rounded pl-8 pr-3 py-1.5 text-white placeholder-soc-muted focus:outline-none focus:border-cyan-500 transition"
          />
        </div>

        {/* Honeypot selector */}
        <div className="flex items-center space-x-1">
          <span className="text-soc-muted">Honeypot:</span>
          <select
            value={selectedHoneypot}
            onChange={(e) => setSelectedHoneypot(e.target.value)}
            className="bg-soc-surface border border-soc-border rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-cyan-500"
          >
            <option value="all">ALL HONEYPOTS</option>
            <option value="cowrie">Cowrie (SSH/Telnet)</option>
            <option value="opencanary">OpenCanary (Web/SMB)</option>
            <option value="dionaea">Dionaea (SMB/MSSQL)</option>
            <option value="conpot">Conpot (ICS/SCADA)</option>
          </select>
        </div>

        {/* Severity filter */}
        <div className="flex items-center space-x-1">
          <span className="text-soc-muted">Severity:</span>
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="bg-soc-surface border border-soc-border rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-cyan-500"
          >
            <option value="all">ALL SEVERITIES</option>
            <option value="critical">Critical (&ge;76)</option>
            <option value="high">High (51-75)</option>
            <option value="medium">Medium (26-50)</option>
            <option value="low">Low (&le;25)</option>
          </select>
        </div>
      </div>

      {/* Events Table */}
      <div className="rounded border border-soc-border bg-soc-surface overflow-hidden shadow-2xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-soc-card/90 text-soc-muted border-b border-soc-border">
              <tr>
                <th className="py-2.5 px-3 w-8"></th>
                <th className="py-2.5 px-3">TIMESTAMP</th>
                <th className="py-2.5 px-3">SOURCE IP</th>
                <th className="py-2.5 px-3">HONEYPOT</th>
                <th className="py-2.5 px-3">EVENT TYPE</th>
                <th className="py-2.5 px-3">PAYLOAD / COMMAND</th>
                <th className="py-2.5 px-3 text-right">SEVERITY</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border/60">
              {filteredEvents.length > 0 ? (
                filteredEvents.slice(0, 150).map((ev) => {
                  const isExpanded = expandedRowId === ev.id;
                  const currentMode = viewMode[ev.id] || 'normalised';
                  const band = ev.risk_band || 'low';
                  const attackerId = ipToIdMap[ev.src_ip] || ev.attacker_id;

                  return (
                    <React.Fragment key={ev.id || ev.event_id}>
                      <tr className="hover:bg-soc-card/60 transition group cursor-pointer">
                        <td className="py-2 px-3 text-soc-muted" onClick={() => toggleRow(ev.id)}>
                          {isExpanded ? (
                            <ChevronDown className="h-3.5 w-3.5 text-cyan-400" />
                          ) : (
                            <ChevronRight className="h-3.5 w-3.5" />
                          )}
                        </td>

                        <td className="py-2 px-3 text-soc-muted whitespace-nowrap" onClick={() => toggleRow(ev.id)}>
                          {new Date(ev.timestamp || ev.received_at).toLocaleTimeString()}
                        </td>

                        <td className="py-2 px-3">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              if (attackerId) setSelectedAttackerId(attackerId);
                            }}
                            className="font-bold text-cyan-300 hover:text-cyan-100 hover:underline flex items-center space-x-1"
                          >
                            <span>{ev.src_ip}</span>
                            <span className="text-[10px] text-soc-muted opacity-0 group-hover:opacity-100 transition">
                              &rarr;
                            </span>
                          </button>
                        </td>

                        <td className="py-2 px-3 uppercase text-soc-muted" onClick={() => toggleRow(ev.id)}>
                          <span className="text-white">{ev.honeypot}</span>
                          {ev.decoy_type === 'internal' && (
                            <span className="ml-1 text-[9px] bg-red-950 text-red-400 px-1 py-0.2 rounded border border-red-500/40">
                              INT
                            </span>
                          )}
                        </td>

                        <td className="py-2 px-3 uppercase text-white font-medium" onClick={() => toggleRow(ev.id)}>
                          {ev.event_type}
                        </td>

                        <td className="py-2 px-3 truncate max-w-xs text-soc-muted" onClick={() => toggleRow(ev.id)}>
                          {ev.command ? (
                            <span className="text-emerald-400 font-mono">$ {ev.command}</span>
                          ) : ev.username ? (
                            <span>Auth: {ev.username}</span>
                          ) : (
                            <span className="text-soc-muted italic">telemetry ping</span>
                          )}
                        </td>

                        <td className="py-2 px-3 text-right" onClick={() => toggleRow(ev.id)}>
                          <span
                            className={`inline-block px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${getSeverityBadge(
                              band
                            )}`}
                          >
                            {band}
                          </span>
                        </td>
                      </tr>

                      {/* Expanded JSON Inspector Row */}
                      {isExpanded && (
                        <tr className="bg-black/80">
                          <td colSpan={7} className="p-4 border-t border-b border-cyan-500/30">
                            <div className="space-y-3">
                              <div className="flex items-center justify-between border-b border-gray-800 pb-2">
                                <div className="flex items-center space-x-2">
                                  <Code className="h-4 w-4 text-cyan-400" />
                                  <span className="font-bold text-white text-xs">EVENT INSPECTOR ({ev.event_id})</span>
                                </div>
                                <div className="flex items-center space-x-1 text-[11px]">
                                  <button
                                    onClick={() => setViewMode({ ...viewMode, [ev.id]: 'normalised' })}
                                    className={`px-2 py-0.5 rounded ${currentMode === 'normalised'
                                        ? 'bg-cyan-500 text-black font-bold'
                                        : 'bg-soc-card text-soc-muted'
                                      }`}
                                  >
                                    NORMALISED JSON
                                  </button>
                                  <button
                                    onClick={() => setViewMode({ ...viewMode, [ev.id]: 'raw' })}
                                    className={`px-2 py-0.5 rounded ${currentMode === 'raw'
                                        ? 'bg-cyan-500 text-black font-bold'
                                        : 'bg-soc-card text-soc-muted'
                                      }`}
                                  >
                                    RAW LOG
                                  </button>
                                </div>
                              </div>

                              <pre className="p-3 rounded bg-black text-cyan-300 font-mono text-[11px] overflow-x-auto max-h-60 border border-gray-800 scanlines">
                                {JSON.stringify(
                                  currentMode === 'raw' ? ev.raw || ev : ev.normalised || ev,
                                  null,
                                  2
                                )}
                              </pre>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={7} className="text-center py-12 text-soc-muted">
                    No matching deception events captured.
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

