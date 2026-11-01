import React, { createContext, useContext, useState, useEffect, useRef, useCallback } from 'react';
import { api } from '../api/client';

const SocContext = createContext(null);

function resolveWsUrl() {
  const envWs = import.meta.env.VITE_WS_URL;
  if (typeof window !== 'undefined' && window.location) {
    const currentHost = window.location.hostname;
    const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    if (currentHost === 'localhost' || currentHost === '127.0.0.1') {
      return `${wsProto}//127.0.0.1:8000/ws/live`;
    }
    if (currentHost) {
      return `${wsProto}//${currentHost}:8000/ws/live`;
    }
    if (envWs && envWs.trim()) {
      return envWs.trim();
    }
  }
  return (envWs || 'ws://localhost:8000/ws/live').trim();
}

export function SocProvider({ children }) {
  const [isDemoMode] = useState(false);
  const [isLiveConnected, setIsLiveConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [backendError, setBackendError] = useState(null);

  // Core Real Telemetry Data (no mock/demo fallback)
  const [overview, setOverview] = useState(null);
  const [events, setEvents] = useState([]);
  const [isEventsPaused, setIsEventsPaused] = useState(false);
  const isEventsPausedRef = useRef(false);
  isEventsPausedRef.current = isEventsPaused;

  const [attackers, setAttackers] = useState([]);
  const [honeypots, setHoneypots] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [relationships, setRelationships] = useState([]);
  const [blocks, setBlocks] = useState([]);
  const [actions, setActions] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [functionEvents, setFunctionEvents] = useState([]);
  const [functionStats, setFunctionStats] = useState(null);
  const [latestRiskScoreUpdate, setLatestRiskScoreUpdate] = useState(null);
  const [latestSessionTransition, setLatestSessionTransition] = useState(null);
  const [sessionTransitions, setSessionTransitions] = useState([]);

  // UI Toast notification state
  const [toasts, setToasts] = useState([]);
  const addToast = useCallback((msg, type = 'info') => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev, { id, msg, type }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4000);
  }, []);

  // Simulation narrator overlay state
  const [narrator, setNarrator] = useState(null);

  // Selected for drawers / modals
  const [selectedAttackerId, setSelectedAttackerId] = useState(null);
  const [selectedHoneypot, setSelectedHoneypot] = useState(null);

  // Incoming animation pulses
  const [incomingPing, setIncomingPing] = useState(null);

  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);

  // Fetch actual data from real FastAPI backend
  const refreshAllData = useCallback(async () => {
    try {
      // 1. Check dedicated lightweight health check
      const healthCheck = await api.checkHealth();
      if (!healthCheck.ok) {
        throw new Error(healthCheck.error || `Health probe failed (HTTP ${healthCheck.status})`);
      }

      // 2. Fetch endpoints in parallel with resilient fallbacks for honeypot infrastructure
      const [ovData, evData, atkData, hpData, incData, relData, blkData, metData, actData, fnStatsData, fnEvData] = await Promise.all([
        api.getOverview(),
        api.getEvents({ limit: 100 }),
        api.getAttackers(),
        api.getHoneypotHealth().catch((e) => {
          console.warn('Honeypot container health warning (non-fatal):', e.message);
          return { honeypots: [] };
        }),
        api.getIncidents().catch(() => ({ incidents: [] })),
        api.getRelationships().catch(() => ({ relationships: [] })),
        api.getBlocks().catch(() => ({ blocks: [] })),
        api.getMetrics().catch(() => null),
        api.getActions().catch(() => []),
        api.getFunctionStats().catch(() => null),
        api.getFunctionEvents({ limit: 50 }).catch(() => ({ events: [] })),
      ]);

      setBackendError(null);
      setOverview(ovData);
      setEvents(evData?.events || []);
      setAttackers(atkData?.attackers || []);
      setHoneypots(hpData?.honeypots || []);
      setIncidents(incData?.incidents || []);
      setRelationships(relData?.relationships || []);
      setBlocks(blkData?.blocks || []);
      setMetrics(metData || null);
      setActions(actData || []);
      setFunctionStats(fnStatsData || null);
      setFunctionEvents(fnEvData?.events || []);
    } catch (err) {
      console.error('Backend connection failed:', err.message);
      setBackendError(err.message || 'Backend connection failed');
      // Do not populate mock/demo data — surface real error/loading states
      setOverview(null);
      setEvents([]);
      setAttackers([]);
      setHoneypots([]);
      setIncidents([]);
      setRelationships([]);
      setBlocks([]);
      setMetrics(null);
      setActions([]);
    } finally {
      setLoading(false);
    }
  }, []);

  // WebSocket Connection using configured VITE_WS_URL
  useEffect(() => {
    let unmounted = false;

    function connectWs() {
      if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) return;

      const wsUrl = resolveWsUrl();

      try {
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          if (!unmounted) {
            setIsLiveConnected(true);
            console.log(`SENTINEL SOC Live WebSocket connected to ${wsUrl}`);
          }
        };

        ws.onmessage = (msgEv) => {
          try {
            const data = JSON.parse(msgEv.data);
            const { type, payload } = data;

            if (type === 'event') {
              if (!isEventsPausedRef.current) {
                setEvents((prev) => [payload, ...prev.slice(0, 199)]);
              }
              setIncomingPing({ ...payload, ts: Date.now() });

              // update overview count
              setOverview((prev) => (prev ? { ...prev, total_events: (prev.total_events || 0) + 1 } : prev));
            } else if (type === 'attacker_update') {
              setAttackers((prev) => {
                const idx = prev.findIndex((a) => a.id === payload.id || a.ip === payload.ip);
                if (idx >= 0) {
                  const updated = [...prev];
                  updated[idx] = { ...updated[idx], ...payload };
                  return updated;
                }
                return [payload, ...prev];
              });
            } else if (type === 'relationship') {
              setRelationships((prev) => {
                const exists = prev.some((r) => r.id === payload.id);
                if (!exists) {
                  addToast(`New Correlation: ${payload.attacker_a_ip} <-> ${payload.attacker_b_ip}`, 'info');
                  return [payload, ...prev];
                }
                return prev;
              });
            } else if (type === 'incident') {
              setIncidents((prev) => {
                const idx = prev.findIndex((i) => i.id === payload.id);
                if (idx >= 0) {
                  const updated = [...prev];
                  updated[idx] = { ...updated[idx], ...payload };
                  return updated;
                }
                addToast(`Critical Incident: ${payload.title}`, 'error');
                return [payload, ...prev];
              });
              setOverview((prev) => (prev ? { ...prev, total_incidents: (prev.total_incidents || 0) + 1 } : prev));
            } else if (type === 'function_targeting') {
              setFunctionEvents((prev) => [payload, ...prev.slice(0, 99)]);
              setFunctionStats((prev) => {
                if (!prev) return prev;
                return {
                  ...prev,
                  total_targeted_events: (prev.total_targeted_events || 0) + 1,
                };
              });
              addToast(`Function Target: ${payload.target_function} (${payload.src_ip})`, 'warning');
            } else if (type === 'action') {
              setActions((prev) => {
                const idx = prev.findIndex((a) => a.id === payload.id);
                if (idx >= 0) {
                  const upd = [...prev];
                  upd[idx] = { ...upd[idx], ...payload };
                  return upd;
                }
                addToast(`Action Proposed: ${payload.action_type} on ${payload.target_ip}`, 'warning');
                return [payload, ...prev];
              });
            } else if (type === 'block') {
              setBlocks((prev) => {
                const idx = prev.findIndex((b) => b.id === payload.block_id || b.ip === payload.ip);
                if (idx >= 0) {
                  const updated = [...prev];
                  updated[idx] = { ...updated[idx], ...payload, status: 'active' };
                  return updated;
                }
                return [
                  {
                    id: payload.block_id || Date.now(),
                    ip: payload.ip,
                    status: 'active',
                    requested_by: payload.requested_by || 'auto',
                    ttl_seconds: payload.ttl_seconds || 600,
                    expires_at: new Date(Date.now() + 600000).toISOString(),
                  },
                  ...prev,
                ];
              });
              setAttackers((prev) =>
                prev.map((a) => (a.ip === payload.ip ? { ...a, status: 'blocked' } : a))
              );
              setOverview((prev) => (prev ? { ...prev, active_blocks: (prev.active_blocks || 0) + 1 } : prev));
              addToast(`Firewall Block Verified: ${payload.ip}`, 'warning');
            } else if (type === 'rollback') {
              setBlocks((prev) =>
                prev.map((b) => (b.ip === payload.ip ? { ...b, status: 'rolled_back' } : b))
              );
              setAttackers((prev) =>
                prev.map((a) => (a.ip === payload.ip ? { ...a, status: 'active' } : a))
              );
              setOverview((prev) => (prev ? { ...prev, active_blocks: Math.max(0, (prev.active_blocks || 1) - 1) } : prev));
              addToast(`Auto-Rollback Complete: ${payload.ip} unblocked`, 'info');
            } else if (type === 'session_transition') {
              setLatestSessionTransition(payload);
              setSessionTransitions((prev) => [payload, ...prev.slice(0, 49)]);
              addToast(`SESSION DIVERTED: REAL → DECOY for ${payload.session_id} (${payload.reason || 'Critical security violation'})`, 'error');
            } else if (type === 'risk_score_update') {
              setLatestRiskScoreUpdate(payload);
              if (payload.routing_transition) {
                setLatestSessionTransition(payload.routing_transition);
                setSessionTransitions((prev) => [payload.routing_transition, ...prev.slice(0, 49)]);
                addToast(`DIVERSION EVENT: ${payload.routing_transition.transition} (${payload.src_ip})`, 'error');
              }
            }
          } catch (e) {
            console.error('Error parsing WS message:', e);
          }
        };

        ws.onclose = () => {
          if (!unmounted) {
            setIsLiveConnected(false);
            reconnectTimeoutRef.current = setTimeout(connectWs, 3000);
          }
        };

        ws.onerror = () => {
          ws.close();
        };
      } catch (err) {
        setIsLiveConnected(false);
        reconnectTimeoutRef.current = setTimeout(connectWs, 5000);
      }
    }

    refreshAllData();
    connectWs();

    const pollInterval = setInterval(() => {
      refreshAllData();
    }, 15000);

    // Dedicated fast-polling health recovery worker (5s)
    const healthInterval = setInterval(async () => {
      try {
        const h = await api.checkHealth();
        if (h.ok) {
          setBackendError((prevErr) => {
            if (prevErr) {
              console.log('Backend health restored; triggering automatic data recovery...');
              refreshAllData();
              return null;
            }
            return null;
          });
        }
      } catch {
        // Handled silently by health probe
      }
    }, 5000);

    return () => {
      unmounted = true;
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      clearInterval(pollInterval);
      clearInterval(healthInterval);
      if (wsRef.current) wsRef.current.close();
    };
  }, [refreshAllData, addToast]);

  // Actions wired to actual backend API
  const blockAttackerAction = async (id, ip) => {
    try {
      await api.blockAttacker(id);
      setAttackers((prev) =>
        prev.map((a) => (a.id === id || a.ip === ip ? { ...a, status: 'blocked' } : a))
      );
      setBlocks((prev) => [
        {
          id: Date.now(),
          ip,
          attacker_id: id,
          status: 'active',
          ttl_seconds: 600,
          requested_at: new Date().toISOString(),
          expires_at: new Date(Date.now() + 600000).toISOString(),
        },
        ...prev.filter((b) => b.ip !== ip),
      ]);
      setOverview((prev) => (prev ? { ...prev, active_blocks: (prev.active_blocks || 0) + 1 } : prev));
      addToast(`Firewall block successfully enforced for ${ip}`, 'success');
      return true;
    } catch (e) {
      addToast(`Block failed: ${e.message}`, 'error');
      return false;
    }
  };

  const unblockAttackerAction = async (id, ip) => {
    try {
      await api.unblockAttacker(id);
      setAttackers((prev) =>
        prev.map((a) => (a.id === id || a.ip === ip ? { ...a, status: 'active' } : a))
      );
      setBlocks((prev) =>
        prev.map((b) => (b.ip === ip ? { ...b, status: 'rolled_back' } : b))
      );
      setOverview((prev) => (prev ? { ...prev, active_blocks: Math.max(0, (prev.active_blocks || 1) - 1) } : prev));
      addToast(`Firewall block removed / rolled back for ${ip}`, 'info');
      return true;
    } catch (e) {
      addToast(`Unblock failed: ${e.message}`, 'error');
      return false;
    }
  };

  const approveActionReq = async (actionId) => {
    try {
      const res = await api.approveAction(actionId);
      setActions((prev) => prev.map((a) => (a.id === actionId ? { ...a, status: 'verified', approver: 'analyst' } : a)));
      addToast(`Action #${actionId} approved & block verified`, 'success');
      refreshAllData();
      return res;
    } catch (e) {
      addToast(`Action approval failed: ${e.message}`, 'error');
      throw e;
    }
  };

  const rejectActionReq = async (actionId, reason) => {
    try {
      const res = await api.rejectAction(actionId, 'analyst', reason);
      setActions((prev) => prev.map((a) => (a.id === actionId ? { ...a, status: 'rejected', approver: 'analyst' } : a)));
      addToast(`Action #${actionId} rejected`, 'info');
      return res;
    } catch (e) {
      addToast(`Action rejection failed: ${e.message}`, 'error');
      throw e;
    }
  };

  const runSimulationAction = async (scenario = 'full_chain', speed = 2.0) => {
    try {
      addToast(`Starting attack simulation: ${scenario}`, 'info');
      if (scenario === 'full_chain') {
        setNarrator({
          step: 1,
          title: 'Stage 1: Reconnaissance',
          desc: 'Adversary probes exposed Cowrie SSH honeypot on port 22.',
        });
        setTimeout(() => {
          setNarrator({
            step: 2,
            title: 'Stage 2: Brute Force Attempt',
            desc: 'High-frequency credential stuffing with common usernames/passwords.',
          });
        }, 3000);
        setTimeout(() => {
          setNarrator({
            step: 3,
            title: 'Stage 3: Valid Account Breach',
            desc: 'Attacker gains interactive shell access; begins enumeration (whoami, id).',
          });
        }, 6000);
        setTimeout(() => {
          setNarrator({
            step: 4,
            title: 'Stage 4: Malware Infiltration & Lateral Decoy Probe',
            desc: 'C2 payload staged via wget; internal decoy accessed. Risk velocity reaches 100/100.',
          });
        }, 9000);
        setTimeout(() => {
          setNarrator({
            step: 5,
            title: 'Stage 5: Autonomous Containment',
            desc: 'Firewall block auto-enforced; Incident generated; 600s TTL countdown started.',
          });
        }, 12000);
        setTimeout(() => {
          setNarrator(null);
        }, 16000);
      }
      await api.startSimulation(scenario, speed);
    } catch (e) {
      addToast(`Simulation start error: ${e.message}`, 'error');
    }
  };

  const patchIncidentAction = async (id, data) => {
    try {
      const updated = await api.patchIncident(id, data);
      setIncidents((prev) => prev.map((i) => (i.id === id ? updated : i)));
      addToast(`Incident #${id} updated to ${data.status || 'new status'}`, 'success');
      return updated;
    } catch (e) {
      addToast(`Failed to update incident: ${e.message}`, 'error');
      throw e;
    }
  };

  const addIncidentNoteAction = async (id, noteText, author = 'analyst') => {
    try {
      const updated = await api.addIncidentNote(id, { text: noteText, author });
      setIncidents((prev) => prev.map((i) => (i.id === id ? updated : i)));
      addToast('Investigation note saved', 'success');
      return updated;
    } catch (e) {
      addToast(`Failed to add note: ${e.message}`, 'error');
      throw e;
    }
  };

  return (
    <SocContext.Provider
      value={{
        isDemoMode,
        isLiveConnected,
        isBackendConnected: !backendError,
        loading,
        backendError,
        overview,
        events,
        isEventsPaused,
        setIsEventsPaused,
        attackers,
        honeypots,
        incidents,
        relationships,
        blocks,
        actions,
        metrics,
        functionEvents,
        functionStats,
        refreshFunctionStats: async () => {
          try {
            const [s, ev] = await Promise.all([api.getFunctionStats(), api.getFunctionEvents({ limit: 50 })]);
            setFunctionStats(s);
            setFunctionEvents(ev?.events || []);
          } catch (e) {
            console.error('Failed to refresh function stats', e);
          }
        },
        toasts,
        addToast,
        narrator,
        setNarrator,
        selectedAttackerId,
        setSelectedAttackerId,
        selectedHoneypot,
        setSelectedHoneypot,
        incomingPing,
        latestRiskScoreUpdate,
        latestSessionTransition,
        sessionTransitions,
        refreshAllData,
        blockAttacker: blockAttackerAction,
        unblockAttacker: unblockAttackerAction,
        approveAction: approveActionReq,
        rejectAction: rejectActionReq,
        runSimulation: runSimulationAction,
        patchIncident: patchIncidentAction,
        addIncidentNote: addIncidentNoteAction,
      }}
    >
      {children}
    </SocContext.Provider>
  );
}

export function useSoc() {
  const context = useContext(SocContext);
  if (!context) {
    throw new Error('useSoc must be used within a SocProvider');
  }
  return context;
}
