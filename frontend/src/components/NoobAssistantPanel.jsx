import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Bot,
  Shield,
  ShieldAlert,
  Terminal,
  X,
  ChevronRight,
  Send,
  Loader2,
  AlertTriangle,
  CheckCircle2,
  Wrench,
  Activity,
  Zap,
  Info,
  ExternalLink,
  Minimize2,
  Maximize2,
  RefreshCw,
  Cpu,
} from 'lucide-react';
import { api } from '../api/client';
import { useSoc } from '../context/SocContext';

// Subtle Web Audio alert chime for new incidents (safe & non-blocking)
const playAlertChime = () => {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'sine';
    osc.frequency.setValueAtTime(587.33, ctx.currentTime);
    osc.frequency.exponentialRampToValueAtTime(880, ctx.currentTime + 0.12);
    gain.gain.setValueAtTime(0.05, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.25);
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.25);
  } catch (e) {
    // Non-fatal if audio context restricted
  }
};

export default function NoobAssistantPanel() {
  const navigate = useNavigate();
  const { incidents, pagerdutyIncidents, setSelectedAttackerId } = useSoc();

  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState([
    {
      id: 'welcome',
      role: 'assistant',
      content:
        "**SENTINEL Security Operations Assistant initialized.**\n\nI have direct access to live telemetry, session diversion metrics, active incidents, and Level-2 function targeting. How can I assist your investigation?",
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      tools_executed: [],
    },
  ]);
  const [inputText, setInputText] = useState('');
  const [loading, setLoading] = useState(false);
  const [executingToolName, setExecutingToolName] = useState(null);
  const [actionInProgress, setActionInProgress] = useState(false);

  // New Incident Pop-up Toast
  const [incidentToast, setIncidentToast] = useState(null);
  const knownIncidentIdsRef = useRef(new Set());
  const initialMountRef = useRef(true);

  const messagesEndRef = useRef(null);

  // Auto-scroll chat to latest message
  useEffect(() => {
    if (isOpen) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, isOpen, loading]);

  // Listen for newly detected incidents and notify analyst
  useEffect(() => {
    const allIncidents = [
      ...(incidents || []),
      ...(pagerdutyIncidents || []).map((p) => ({
        id: p.id || p.dedup_key,
        title: p.title || p.summary,
        severity: p.severity || p.priority || 'critical',
        created_at: p.created_at,
      })),
    ];

    if (allIncidents.length === 0) return;

    if (initialMountRef.current) {
      allIncidents.forEach((inc) => knownIncidentIdsRef.current.add(String(inc.id)));
      initialMountRef.current = false;
      return;
    }

    const newlyIdentified = allIncidents.find(
      (inc) => !knownIncidentIdsRef.current.has(String(inc.id))
    );

    if (newlyIdentified) {
      knownIncidentIdsRef.current.add(String(newlyIdentified.id));
      playAlertChime();

      setIncidentToast({
        id: newlyIdentified.id,
        title: newlyIdentified.title,
        severity: newlyIdentified.severity || 'critical',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      });
    }
  }, [incidents, pagerdutyIncidents]);

  // Send message to live backend assistant
  const handleSend = async (customText = null) => {
    const text = (customText || inputText).trim();
    if (!text || loading) return;

    const userMessage = {
      id: `usr_${Date.now()}`,
      role: 'user',
      content: text,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInputText('');
    setLoading(true);
    setExecutingToolName('Analyzing query & selecting telemetry tools...');

    try {
      const historyPayload = messages
        .filter((m) => m.role === 'user' || m.role === 'assistant')
        .slice(-6)
        .map((m) => ({ role: m.role, content: m.content }));

      const res = await api.assistantChat(text, historyPayload);

      const assistantMessage = {
        id: `asst_${Date.now()}`,
        role: 'assistant',
        content: res.reply || 'No response data returned by the security engine.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        tools_executed: res.tools_executed || [],
        evidence: res.evidence || [],
        pending_action: res.pending_action || null,
        meta: res.meta || {},
      };

      setMessages((prev) => [...prev, assistantMessage]);
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          id: `err_${Date.now()}`,
          role: 'assistant',
          content: `⚠️ **Assistant Communication Error:** ${err.message || 'Failed to reach backend assistant API.'}\n\nPlease verify that the backend daemon is operational on port 8000.`,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          isError: true,
        },
      ]);
    } finally {
      setLoading(false);
      setExecutingToolName(null);
    }
  };

  // Handle explicit analyst confirmation for security-modifying actions
  const handleConfirmAction = async (msgId, pendingAction, confirmed) => {
    setActionInProgress(true);
    try {
      const res = await api.confirmAssistantAction(
        pendingAction.action_type,
        pendingAction.payload,
        confirmed
      );

      // Update message state removing pending confirmation and recording result
      setMessages((prev) =>
        prev.map((m) => {
          if (m.id === msgId) {
            return {
              ...m,
              pending_action: null,
              content: `${m.content}\n\n---\n**Analyst Decision:** ${
                confirmed ? '✅ Confirmed & Executed' : '❌ Cancelled'
              }\n*Result:* ${res.message || 'Action processed.'}`,
            };
          }
          return m;
        })
      );
    } catch (err) {
      alert(`Action execution failed: ${err.message}`);
    } finally {
      setActionInProgress(false);
    }
  };

  const suggestedQuestions = [
    'What is happening right now?',
    'Which attacker is the most dangerous?',
    'Why was this visitor redirected to the decoy?',
    'Which functions are being targeted?',
    'Is PagerDuty working?',
    'Investigate the latest critical incident',
  ];

  return (
    <>
      {/* ------------------------------------------------------------------ */}
      {/* NEW INCIDENT TOAST NOTIFICATION (Discreet Enterprise Banner)      */}
      {/* ------------------------------------------------------------------ */}
      {incidentToast && !isOpen && (
        <div className="fixed bottom-16 right-5 z-40 max-w-md w-[calc(100vw-2.5rem)] rounded-lg bg-slate-900 border border-red-500/50 shadow-2xl p-3.5 space-y-2 text-xs font-mono transition-all animate-slide-in">
          <div className="flex items-center justify-between text-red-400">
            <span className="flex items-center space-x-1.5 font-bold uppercase tracking-wider">
              <ShieldAlert className="h-4 w-4" />
              <span>Incident Detected</span>
            </span>
            <div className="flex items-center space-x-2">
              <span className="text-[10px] text-slate-400">{incidentToast.timestamp}</span>
              <button
                onClick={() => setIncidentToast(null)}
                className="text-slate-400 hover:text-white p-0.5 rounded"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
          <div className="text-white font-medium line-clamp-2">{incidentToast.title}</div>
          <div className="flex items-center space-x-2 pt-1">
            <button
              onClick={() => {
                setIsOpen(true);
                handleSend(`Investigate incident: ${incidentToast.title}`);
                setIncidentToast(null);
              }}
              className="flex-1 py-1.5 px-2.5 rounded bg-red-950/80 hover:bg-red-900 border border-red-500/40 text-red-200 font-semibold flex items-center justify-center space-x-1 transition"
            >
              <Bot className="h-3.5 w-3.5" />
              <span>Investigate with Noob</span>
            </button>
            <button
              onClick={() => {
                navigate('/incidents');
                setIncidentToast(null);
              }}
              className="py-1.5 px-2.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition"
            >
              Incident Queue
            </button>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* DOCKED TOGGLE PILL (Bottom-Right, Professional Enterprise Pill)     */}
      {/* ------------------------------------------------------------------ */}
      <div className="fixed bottom-4 right-4 z-40">
        <button
          onClick={() => setIsOpen(!isOpen)}
          className={`flex items-center space-x-2.5 px-3.5 py-2 rounded-lg border font-mono text-xs font-semibold shadow-lg transition ${
            isOpen
              ? 'bg-slate-800 border-slate-600 text-white'
              : 'bg-slate-900 hover:bg-slate-800 border-slate-700 text-slate-200 hover:text-white'
          }`}
        >
          <div className="relative">
            <Bot className="h-4 w-4 text-cyan-400" />
            <span className="absolute -top-0.5 -right-0.5 h-1.5 w-1.5 rounded-full bg-emerald-400"></span>
          </div>
          <span>Noob SOC Assistant</span>
          <span className="text-[10px] text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded border border-slate-700">
            LIVE
          </span>
        </button>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* SLIDE-OVER ASSISTANT DRAWER                                        */}
      {/* ------------------------------------------------------------------ */}
      {isOpen && (
        <div className="fixed inset-y-0 right-0 z-50 w-full sm:w-[480px] lg:w-[520px] bg-slate-950/95 border-l border-slate-800 shadow-2xl backdrop-blur-md flex flex-col font-mono text-xs animate-slide-in">
          {/* Header */}
          <div className="p-3.5 border-b border-slate-800 bg-slate-900/80 flex items-center justify-between">
            <div className="flex items-center space-x-2.5">
              <div className="p-1.5 rounded bg-slate-800 border border-slate-700 text-cyan-400">
                <Bot className="h-4 w-4" />
              </div>
              <div>
                <div className="font-bold text-white tracking-wide flex items-center space-x-2">
                  <span>NOOB SOC ASSISTANT</span>
                  <span className="text-[10px] text-emerald-400 bg-emerald-950/60 px-1.5 py-0.2 rounded border border-emerald-500/30">
                    ONLINE
                  </span>
                </div>
                <div className="text-[10px] text-slate-400 flex items-center space-x-1.5 mt-0.5">
                  <Cpu className="h-3 w-3 text-cyan-400" />
                  <span>Telemetry Tool-Calling Engine</span>
                  <span>&bull;</span>
                  <span>Read-Only Investigation</span>
                </div>
              </div>
            </div>

            <div className="flex items-center space-x-1 text-slate-400">
              <button
                onClick={() =>
                  setMessages([
                    {
                      id: 'cleared',
                      role: 'assistant',
                      content: 'Session history reset. Ready for new security investigation.',
                      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
                    },
                  ])
                }
                title="Reset conversation"
                className="p-1.5 rounded hover:bg-slate-800 hover:text-white transition"
              >
                <RefreshCw className="h-3.5 w-3.5" />
              </button>
              <button
                onClick={() => setIsOpen(false)}
                title="Close assistant"
                className="p-1.5 rounded hover:bg-slate-800 hover:text-white transition"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          </div>

          {/* Messages Feed */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {messages.map((msg) => (
              <div
                key={msg.id}
                className={`flex flex-col ${msg.role === 'user' ? 'items-end' : 'items-start'}`}
              >
                <div className="flex items-center space-x-1.5 text-[10px] text-slate-400 mb-1 px-1">
                  <span>{msg.role === 'user' ? 'Analyst' : 'Noob SOC Assistant'}</span>
                  <span>&bull;</span>
                  <span>{msg.timestamp}</span>
                </div>

                <div
                  className={`max-w-[92%] rounded-lg p-3 space-y-2 border ${
                    msg.role === 'user'
                      ? 'bg-slate-800 border-slate-700 text-slate-100'
                      : msg.isError
                      ? 'bg-red-950/40 border-red-500/40 text-red-200'
                      : 'bg-slate-900 border-slate-800 text-slate-200'
                  }`}
                >
                  {/* Tool execution indicator badges */}
                  {msg.tools_executed && msg.tools_executed.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 pb-1 border-b border-slate-800">
                      {msg.tools_executed.map((t, idx) => (
                        <span
                          key={idx}
                          className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-700 text-[10px] text-cyan-300 flex items-center space-x-1"
                        >
                          <Terminal className="h-2.5 w-2.5 text-cyan-400" />
                          <span>{t.tool}</span>
                        </span>
                      ))}
                    </div>
                  )}

                  {/* Message body (whitespace-pre-line) */}
                  <div className="whitespace-pre-line leading-relaxed text-xs">
                    {msg.content}
                  </div>

                  {/* Security Confirmation Card (Action Permissions) */}
                  {msg.pending_action && msg.pending_action.requires_confirmation && (
                    <div className="mt-2.5 p-2.5 rounded bg-amber-950/40 border border-amber-500/40 space-y-2">
                      <div className="flex items-center space-x-1.5 text-amber-300 font-bold text-[11px]">
                        <AlertTriangle className="h-3.5 w-3.5" />
                        <span>Security Action Requires Analyst Authorization</span>
                      </div>
                      <div className="text-[11px] text-slate-300">
                        {msg.pending_action.impact}
                      </div>
                      <div className="flex items-center space-x-2 pt-1">
                        <button
                          disabled={actionInProgress}
                          onClick={() => handleConfirmAction(msg.id, msg.pending_action, true)}
                          className="px-3 py-1 rounded bg-amber-600 hover:bg-amber-500 text-slate-950 font-bold text-xs flex items-center space-x-1 transition disabled:opacity-50"
                        >
                          {actionInProgress ? <Loader2 className="h-3 w-3 animate-spin" /> : <CheckCircle2 className="h-3 w-3" />}
                          <span>Authorize & Execute</span>
                        </button>
                        <button
                          disabled={actionInProgress}
                          onClick={() => handleConfirmAction(msg.id, msg.pending_action, false)}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition disabled:opacity-50"
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ))}

            {loading && (
              <div className="flex items-center space-x-2 p-3 rounded-lg bg-slate-900 border border-slate-800 text-slate-400">
                <Loader2 className="h-4 w-4 animate-spin text-cyan-400" />
                <span className="text-xs">{executingToolName || 'Querying live telemetry & evaluating evidence...'}</span>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Quick Suggested Queries */}
          <div className="p-2 border-t border-slate-800/80 bg-slate-900/40">
            <div className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider mb-1.5 px-1">
              Suggested Investigations:
            </div>
            <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto">
              {suggestedQuestions.map((q, idx) => (
                <button
                  key={idx}
                  disabled={loading}
                  onClick={() => handleSend(q)}
                  className="px-2 py-1 rounded bg-slate-800/70 hover:bg-slate-800 border border-slate-700/60 hover:border-cyan-500/40 text-[10px] text-slate-300 hover:text-white transition text-left truncate max-w-full"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>

          {/* Input Box */}
          <div className="p-3 border-t border-slate-800 bg-slate-900/90">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleSend();
              }}
              className="flex items-center space-x-2"
            >
              <input
                type="text"
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                placeholder="Ask about incidents, session diversion, targeted APIs..."
                className="flex-1 px-3 py-2 rounded bg-slate-950 border border-slate-700 focus:border-cyan-500 focus:outline-none text-slate-100 placeholder-slate-500 text-xs transition"
              />
              <button
                type="submit"
                disabled={loading || !inputText.trim()}
                className="px-3 py-2 rounded bg-cyan-950 hover:bg-cyan-900 border border-cyan-500/50 text-cyan-200 font-semibold transition disabled:opacity-40"
              >
                <Send className="h-3.5 w-3.5" />
              </button>
            </form>
          </div>
        </div>
      )}
    </>
  );
}

