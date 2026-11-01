import React, { useState } from 'react';
import {
  Server,
  Activity,
  Cpu,
  HardDrive,
  Clock,
  Radio,
  X,
  ShieldAlert,
  ChevronRight,
  Terminal,
} from 'lucide-react';
import { useSoc } from '../context/SocContext';

const HP_DETAILS = {
  cowrie: {
    title: 'Cowrie Honeypot',
    purpose: 'Medium & high interaction SSH / Telnet emulation',
    decoys: 'Port 22, 2222, 23 (Virtual filesystem and interactive shell logging)',
    iconColor: '#00f0ff',
  },
  opencanary: {
    title: 'OpenCanary Deception',
    purpose: 'Modular multi-service decoy: HTTP, SMB, RDP, MySQL, MSSQL',
    decoys: 'Port 80, 8080, 445, 3306 (Internal & External enterprise tripwires)',
    iconColor: '#10b981',
  },
  dionaea: {
    title: 'Dionaea Malware Trap',
    purpose: 'Automated malware collection & vulnerability exploitation decoy',
    decoys: 'Port 445, 139, 1433 (SMB payload capture, shellcode extraction)',
    iconColor: '#a855f7',
  },
  conpot: {
    title: 'Conpot ICS/SCADA',
    purpose: 'Industrial Control Systems & Smart Grid deception infrastructure',
    decoys: 'Port 502 (Modbus), 102 (S7comm), 161 (SNMP), 47808 (BACnet)',
    iconColor: '#eab308',
  },
  decoy_app: {
    title: 'Isolated Decoy Web Application Honeypot',
    purpose: 'Controlled-latency deception trap with honeytoken instrumentation',
    decoys: 'Port 8002 / :8000 (Authentication, OTP, Admin, DB & Payment honeynet traps)',
    iconColor: '#ec4899',
  },
};

export default function Honeypots() {
  const { honeypots, events, setSelectedAttackerId, loading, backendError } = useSoc();
  const [activeDrawerHp, setActiveDrawerHp] = useState(null);

  const getStatusBadge = (status) => {
    switch (status) {
      case 'running':
        return 'bg-emerald-950 text-emerald-400 border-emerald-500/50';
      case 'degraded':
        return 'bg-yellow-950 text-yellow-400 border-yellow-500/50';
      default:
        return 'bg-red-950 text-red-400 border-red-500/50';
    }
  };

  const getHpHits = (hpName) => {
    return events.filter((e) => e.honeypot?.toLowerCase() === hpName.toLowerCase());
  };

  const activeHpObj = honeypots.find((h) => h.honeypot === activeDrawerHp);
  const drawerEvents = activeDrawerHp ? getHpHits(activeDrawerHp) : [];
  const drawerMeta = activeDrawerHp ? HP_DETAILS[activeDrawerHp] || { title: activeDrawerHp, purpose: '', decoys: '', iconColor: '#00f0ff' } : null;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-xl font-bold font-mono text-white tracking-wider flex items-center space-x-2">
          <span>DECEPTION FLEET STATUS</span>
          <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></span>
        </h1>
        <p className="text-xs font-mono text-soc-muted mt-0.5">
          Health telemetry and real-time sensor load across distributed honeypots (Click any card to inspect live log drawer)
        </p>
      </div>

      {/* Honeypot Fleet Cards */}
      {honeypots.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
          {honeypots.map((hp) => {
            const meta = HP_DETAILS[hp.honeypot] || {
              title: hp.honeypot,
              purpose: 'Automated deception sensor',
              decoys: 'Decoy services',
              iconColor: '#00f0ff',
            };
            const hpEvents = getHpHits(hp.honeypot);

            return (
            <div
              key={hp.honeypot}
              onClick={() => setActiveDrawerHp(hp.honeypot)}
              className="p-5 rounded border border-soc-border bg-soc-card hover:border-cyan-500/50 cursor-pointer transition shadow-xl space-y-4 group relative overflow-hidden"
            >
              <div className="flex items-start justify-between">
                <div className="flex items-center space-x-3">
                  <div
                    className="h-10 w-10 rounded flex items-center justify-center border shadow-md group-hover:scale-105 transition"
                    style={{
                      backgroundColor: `${meta.iconColor}15`,
                      borderColor: `${meta.iconColor}40`,
                      color: meta.iconColor,
                    }}
                  >
                    <Server className="h-5 w-5" />
                  </div>
                  <div>
                    <h3 className="font-bold text-white text-sm group-hover:text-cyan-300 transition">
                      {meta.title}
                    </h3>
                    <p className="text-[11px] text-soc-muted mt-0.5">{meta.purpose}</p>
                  </div>
                </div>

                <span
                  className={`px-2.5 py-0.5 rounded text-[10px] uppercase font-bold border ${getStatusBadge(
                    hp.status
                  )}`}
                >
                  {hp.status}
                </span>
              </div>

              {/* Decoys monitored */}
              <div className="p-2.5 rounded bg-soc-surface border border-soc-border/60 text-[11px]">
                <span className="text-soc-muted block mb-0.5">Monitored Services:</span>
                <span className="text-gray-300">{meta.decoys}</span>
              </div>

              {/* Stats Bar: CPU, Mem, Events */}
              <div className="grid grid-cols-3 gap-2 text-center pt-1 border-t border-soc-border">
                <div className="p-2 rounded bg-soc-surface/50">
                  <div className="text-[10px] text-soc-muted flex items-center justify-center space-x-1">
                    <Cpu className="h-3 w-3" />
                    <span>CPU LOAD</span>
                  </div>
                  <div className="font-bold text-white mt-1">
                    {hp.cpu_pct !== undefined && hp.cpu_pct !== null ? `${hp.cpu_pct}%` : 'N/A'}
                  </div>
                </div>

                <div className="p-2 rounded bg-soc-surface/50">
                  <div className="text-[10px] text-soc-muted flex items-center justify-center space-x-1">
                    <HardDrive className="h-3 w-3" />
                    <span>MEMORY</span>
                  </div>
                  <div className="font-bold text-white mt-1">
                    {hp.mem_mb !== undefined && hp.mem_mb !== null ? `${hp.mem_mb} MB` : 'N/A'}
                  </div>
                </div>

                <div className="p-2 rounded bg-soc-surface/50">
                  <div className="text-[10px] text-soc-muted flex items-center justify-center space-x-1">
                    <Radio className="h-3 w-3" />
                    <span>TRAPPED</span>
                  </div>
                  <div className="font-bold text-cyan-300 mt-1">{hpEvents.length} events</div>
                </div>
              </div>

              <div className="flex items-center justify-between text-[10px] text-soc-muted pt-1">
                <span className="flex items-center space-x-1">
                  <Clock className="h-3 w-3" />
                  <span>Heartbeat: {hp.last_heartbeat ? new Date(hp.last_heartbeat).toLocaleTimeString() : 'Active'}</span>
                </span>
                <span className="text-cyan-400 group-hover:translate-x-1 transition flex items-center">
                  Inspect Logs <ChevronRight className="h-3 w-3 ml-0.5" />
                </span>
              </div>
            </div>
          );
        })}
      </div>
      ) : (
        <div className="p-8 rounded border border-soc-border bg-soc-card text-center text-xs font-mono text-soc-muted">
          {loading ? 'Polling honeypot fleet health telemetry...' : 'No honeypots detected or backend unreachable.'}
        </div>
      )}

      {/* Slide-out Drawer for Selected Honeypot Logs & Health */}
      {activeDrawerHp && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm animate-fade-in font-mono text-xs">
          <div className="w-full max-w-xl h-full bg-soc-surface border-l border-soc-border shadow-2xl flex flex-col p-6 space-y-5 overflow-y-auto">
            {/* Drawer Header */}
            <div className="flex items-start justify-between border-b border-soc-border pb-4">
              <div className="flex items-center space-x-3">
                <div
                  className="h-10 w-10 rounded flex items-center justify-center border"
                  style={{
                    backgroundColor: `${drawerMeta?.iconColor}20`,
                    borderColor: `${drawerMeta?.iconColor}50`,
                    color: drawerMeta?.iconColor,
                  }}
                >
                  <Server className="h-5 w-5" />
                </div>
                <div>
                  <h2 className="text-base font-bold text-white uppercase">{drawerMeta?.title}</h2>
                  <p className="text-[11px] text-soc-muted">{drawerMeta?.purpose}</p>
                </div>
              </div>

              <button
                onClick={() => setActiveDrawerHp(null)}
                className="p-1 rounded bg-soc-card border border-soc-border text-soc-muted hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

              {/* Metrics Snapshot */}
              <div className="grid grid-cols-3 gap-3">
                <div className="p-3 rounded bg-soc-card border border-soc-border text-center">
                  <span className="text-soc-muted text-[10px] uppercase block">Current Status</span>
                  <span className="font-bold text-emerald-400 text-sm mt-1 block uppercase">
                    {activeHpObj?.status || 'running'}
                  </span>
                </div>
                  <div className="p-3 rounded bg-soc-card border border-soc-border text-center">
                    <span className="text-soc-muted text-[10px] uppercase block">CPU Utilization</span>
                    <span className="font-bold text-white text-sm mt-1 block">
                      {activeHpObj?.cpu_pct ?? 15.4}%
                    </span>
                  </div>
                  <div className="p-3 rounded bg-soc-card border border-soc-border text-center">
                    <span className="text-soc-muted text-[10px] uppercase block">Intercepted Events</span>
                    <span className="font-bold text-cyan-300 text-sm mt-1 block">
                      {drawerEvents.length}
                    </span>
                  </div>
                </div>

                          {/* Recent Trapped Events / Shell Sessions */}
                          <div className="space-y-3 flex-1 flex flex-col">
                            <div className="flex items-center justify-between">
                              <span className="text-xs uppercase font-bold text-white flex items-center space-x-1.5">
                                <Terminal className="h-4 w-4 text-cyan-400" />
                                <span>Recent Intercepted Packets ({drawerEvents.length})</span>
                              </span>
                            </div>

                            <div className="flex-1 rounded border border-soc-border bg-black/60 p-3 space-y-2 overflow-y-auto max-h-96">
                              {drawerEvents.length > 0 ? (
                                drawerEvents.slice(0, 50).map((ev, i) => (
                    <div
                      key={ev.id || i}
                      className="p-2.5 rounded bg-soc-surface/60 border border-soc-border/60 hover:border-cyan-500/50 space-y-1"
                    >
                      <div className="flex items-center justify-between text-[11px]">
                        <button
                          onClick={() => {
                            if (ev.attacker_id) {
                              setSelectedAttackerId(ev.attacker_id);
                              setActiveDrawerHp(null);
                            }
                          }}
                          className="font-bold text-cyan-300 hover:underline flex items-center space-x-1"
                        >
                          <span>{ev.src_ip}</span>
                          <span className="text-[10px] text-soc-muted">&rarr;</span>
                        </button>
                        <span className="text-soc-muted text-[10px]">
                          {new Date(ev.timestamp || ev.received_at).toLocaleTimeString()}
                        </span>
                      </div>

                      <div className="flex items-center justify-between text-[11px]">
                        <span className="uppercase text-white font-medium">{ev.event_type}</span>
                        <span className="text-soc-muted">Port {ev.dst_port || 22}</span>
                      </div>

                      {ev.command && (
                        <div className="text-emerald-400 bg-black/50 p-1 rounded font-mono text-[10px] truncate">
                          $ {ev.command}
                        </div>
                      )}
                      {ev.username && (
                        <div className="text-yellow-300 text-[10px]">
                          Credentials: {ev.username} / {ev.password || '******'}
                        </div>
                      )}
                    </div>
                                ))
                              ) : (
                                <div className="text-center py-12 text-soc-muted">
                                  No events captured on this sensor yet.
                                </div>
                )}
                            </div>
                          </div>

                          <div className="pt-2 border-t border-soc-border flex justify-end">
                            <button
                              onClick={() => setActiveDrawerHp(null)}
                              className="px-4 py-2 rounded bg-soc-card border border-soc-border text-white hover:border-cyan-400 transition"
                            >
                              CLOSE DRAWER
                            </button>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                  );
}
