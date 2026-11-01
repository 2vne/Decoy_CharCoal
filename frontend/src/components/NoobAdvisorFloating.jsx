import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Bot,
  Sparkles,
  X,
  Wrench,
  CheckCircle2,
  ShieldAlert,
  ArrowRight,
  RefreshCw,
  Send,
  MessageSquare,
  AlertTriangle,
  ChevronRight,
  Maximize2,
  Minimize2,
  Zap,
  Flame,
  HelpCircle,
} from 'lucide-react';
import { api } from '../api/client';
import { useSoc } from '../context/SocContext';

// Synthesize pleasant non-intrusive alert sound using Web Audio API
const playAlertChime = () => {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'sine';
    osc.frequency.setValueAtTime(587.33, ctx.currentTime); // D5
    osc.frequency.exponentialRampToValueAtTime(880, ctx.currentTime + 0.12); // A5
    gain.gain.setValueAtTime(0.08, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.28);
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.28);
  } catch (e) {
    // Non-fatal if audio context restricted before user interaction
  }
};

export default function NoobAdvisorFloating() {
  const navigate = useNavigate();
  const { incidents, pagerdutyIncidents } = useSoc();

  // Floating & Dialog state
  const [isOpen, setIsOpen] = useState(false);
  const [activeTab, setActiveTab] = useState('chat'); // 'chat' | 'fixes' | 'incidents'
  const [loading, setLoading] = useState(false);
  const [advisorySummary, setAdvisorySummary] = useState(null);

  // Active Incident Pop-up Banner state
  const [activeIncidentPopup, setActiveIncidentPopup] = useState(null);
  const [popupDismissed, setPopupDismissed] = useState(false);
  const knownIncidentIdsRef = useRef(new Set());
  const initialMountRef = useRef(true);

  // Chat conversation state
  const [chatMessages, setChatMessages] = useState([
    {
      id: 'welcome',
      sender: 'noob',
      text: "👋 Hi! I'm noob, your Autonomous Remediation Advisor. I analyze live attack evidence and provide playbook-driven fixes for detected security incidents. How can I help you defend the perimeter?",
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      quickPicks: [
        'What should I fix first?',
        'Explain latest incident',
        'How to prevent credential stuffing?',
        'Summarize gateway health',
      ],
    },
  ]);
  const [inputMessage, setInputMessage] = useState('');
  const chatScrollRef = useRef(null);

  // Auto-scroll chat to latest message
  useEffect(() => {
    if (activeTab === 'chat' && chatScrollRef.current) {
      chatScrollRef.current.scrollTop = chatScrollRef.current.scrollHeight;
    }
  }, [chatMessages, activeTab, isOpen]);

  // Fetch playbook advisory summary
  const fetchAdvisory = async () => {
    setLoading(true);
    try {
      const data = await api.getAdvisorySummary();
      setAdvisorySummary(data);
    } catch (err) {
      console.warn('[noob] Failed to load advisory summary:', err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAdvisory();
    const interval = setInterval(fetchAdvisory, 25000);
    return () => clearInterval(interval);
  }, []);

  // --------------------------------------------------------------------------
  // LIVE INCIDENT POPUP TRIGGER: Trigger alert popup on every identified incident
  // --------------------------------------------------------------------------
  useEffect(() => {
    const allIncidents = [
      ...(incidents || []),
      ...(pagerdutyIncidents || []).map((p) => ({
        id: p.id || p.dedup_key,
        title: p.title || p.summary,
        severity: p.severity || p.priority || 'critical',
        source: p.source || 'PagerDuty',
        created_at: p.created_at,
        is_pagerduty: true,
      })),
    ];

    if (allIncidents.length === 0) return;

    // Skip all initial existing incidents on page load to prevent stale popups
    if (initialMountRef.current) {
      allIncidents.forEach((inc) => knownIncidentIdsRef.current.add(String(inc.id)));
      initialMountRef.current = false;
      return;
    }

    // Identify newly arrived incident
    const newlyIdentified = allIncidents.find(
      (inc) => !knownIncidentIdsRef.current.has(String(inc.id))
    );

    if (newlyIdentified) {
      knownIncidentIdsRef.current.add(String(newlyIdentified.id));
      playAlertChime();

      // Derive top immediate fix
      const topFix = advisorySummary?.top_recurring_fixes?.[0]?.step ||
        'Deploy progressive rate limiting and isolate attacker session to decoy.';

      setActiveIncidentPopup({
        id: newlyIdentified.id,
        title: newlyIdentified.title,
        severity: newlyIdentified.severity || 'critical',
        source: newlyIdentified.source || 'MIRAGE Deception Gateway',
        topFix,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      });
      setPopupDismissed(false);

      // Also append proactive message into noob's chat stream
      setChatMessages((prev) => [
        ...prev,
        {
          id: `inc_${Date.now()}`,
          sender: 'noob',
          text: `🚨 **NEW INCIDENT IDENTIFIED:** "${newlyIdentified.title}"\n\n**Immediate AI Suggestion:**\n• ${topFix}\n\n*(AI suggestion, human review required)*`,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          incidentId: newlyIdentified.id,
          quickPicks: ['Inspect full incident', 'Apply mitigation playbook', 'Dismiss'],
        },
      ]);
    }
  }, [incidents, pagerdutyIncidents, advisorySummary]);

  // --------------------------------------------------------------------------
  // CHATBOT INTERACTION ENGINE: Intelligent context-aware answers
  // --------------------------------------------------------------------------
  const handleSendMessage = (textToSend = null) => {
    const text = (textToSend || inputMessage).trim();
    if (!text) return;

    const userMsg = {
      id: `usr_${Date.now()}`,
      sender: 'user',
      text,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setChatMessages((prev) => [...prev, userMsg]);
    setInputMessage('');

    // Generate intelligent AI advice response based on live context
    setTimeout(() => {
      const lower = text.toLowerCase();
      let reply = '';
      let quickPicks = [];

      const topFixes = advisorySummary?.top_recurring_fixes || [];
      const activeInc = incidents?.[0];

      if (lower.includes('fix') || lower.includes('what should i') || lower.includes('recommend') || lower.includes('mitigat')) {
        if (topFixes.length > 0) {
          const list = topFixes.slice(0, 3).map((f, i) => `${i + 1}. **${f.step}**\n   ↳ *Why:* ${f.why}`).join('\n\n');
          reply = `Here are the top priority fixes from the MIRAGE Playbook Knowledge Base:\n\n${list}\n\n*AI suggestion, human review required.*`;
          quickPicks = ['View all playbooks', 'Explain incident blast radius'];
        } else {
          reply = 'All monitored perimeters are currently healthy! In case of an attack, I will automatically cross-reference observed IOCs with the 11 integrated YAML playbooks to recommend verified remediation steps.';
        }
      } else if (lower.includes('credential') || lower.includes('auth') || lower.includes('password') || lower.includes('login')) {
        reply = '🛡️ **Playbook pb_credential_stuffing (T1110) Advice:**\n\n1. Enforce progressive rate limiting on `/api/v1/auth/login` and `/auth/otp/verify`.\n2. Invalidate compromised sessions and mandate step-up MFA challenge.\n3. Transition critical administrative endpoints to FIDO2 WebAuthn passwordless authentication.\n\n*AI suggestion, human review required.*';
        quickPicks = ['Is auth gateway in watch mode?', 'Run verification probe'];
      } else if (lower.includes('incident') || lower.includes('threat') || lower.includes('attack')) {
        if (activeInc) {
          reply = `⚠️ **Active Incident Analysis (INC-${activeInc.id}):**\n\n**Title:** ${activeInc.title}\n**Status:** ${activeInc.status.toUpperCase()}\n**Severity:** ${activeInc.severity || 'CRITICAL'}\n\nWould you like me to guide you through the containment protocol?`;
          quickPicks = ['Contain incident', 'Open Incident Queue'];
        } else {
          reply = 'Currently, zero open uncontained incidents are flagged. The deception honeypot fleet is calm and awaiting adversary probes.';
        }
      } else if (lower.includes('gateway') || lower.includes('watch') || lower.includes('fail') || lower.includes('takedown')) {
        reply = '⚡ **Gateway Lifecycle Protocol:**\n\nWhen a gateway route suffers a critical attack (risk >= 51), MIRAGE transitions it through: **Attacked → Taken Down → Patched → Restored → Re-attack Monitored (120m Watch Mode)**. If the adversary re-attacks during watch mode, priority escalation triggers immediately.';
        quickPicks = ['Open Gateway Failures Page', 'Check watch timers'];
      } else if (lower.includes('contain') || lower.includes('apply')) {
        reply = '✅ **Recommended Immediate Containment Action:**\n\n• Route attacker session traffic into the high-interaction isolated decoy honeypot (`REAL → DECOY` session diversion).\n• Retain production secrets safely out of attacker reach while logging telemetry for forensics.';
        quickPicks = ['View Decoy Observation', 'Check Attacker Risk'];
      } else {
        reply = `I have analyzed your query regarding "${text}". MIRAGE's Autonomous Advisor maps real-time attack fingerprints into verified playbook remediations.\n\nKey next step: Review active incident telemetry in the Incident Queue or consult the recommended fixes tab above.`;
        quickPicks = ['What should I fix first?', 'Summarize gateway health'];
      }

      setChatMessages((prev) => [
        ...prev,
        {
          id: `noob_${Date.now()}`,
          sender: 'noob',
          text: reply,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          quickPicks,
        },
      ]);
    }, 450);
  };

  const topFixes = advisorySummary?.top_recurring_fixes || [];

  return (
    <div className="fixed bottom-3 right-3 sm:bottom-5 sm:right-5 z-50 font-mono select-none">
      {/* ------------------------------------------------------------------ */}
      {/* REAL-TIME INCIDENT NOTIFICATION POPUP CARD                        */}
      {/* ------------------------------------------------------------------ */}
      {activeIncidentPopup && !popupDismissed && !isOpen && (
        <div className="absolute bottom-16 right-0 mb-2 w-[calc(100vw-2rem)] sm:w-96 max-w-sm rounded-xl bg-slate-950/95 border-2 border-red-500 shadow-[0_0_35px_rgba(239,68,68,0.45)] backdrop-blur-xl p-3.5 space-y-2.5 animate-slide-in">
          {/* Popup Header */}
          <div className="flex items-start justify-between">
            <div className="flex items-center space-x-2">
              <div className="relative">
                <span className="flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-red-500"></span>
                </span>
              </div>
              <span className="text-xs font-extrabold text-red-400 tracking-wider flex items-center gap-1">
                <ShieldAlert className="w-3.5 h-3.5" />
                INCIDENT IDENTIFIED
              </span>
            </div>
            <div className="flex items-center space-x-1">
              <span className="text-[10px] text-slate-400">{activeIncidentPopup.timestamp}</span>
              <button
                onClick={() => setPopupDismissed(true)}
                className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white transition"
                title="Dismiss popup"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Incident Details */}
          <div className="space-y-1">
            <div className="text-xs font-bold text-white leading-snug line-clamp-2">
              {activeIncidentPopup.title}
            </div>
            <div className="text-[10px] text-red-300/90 bg-red-950/60 p-1.5 rounded border border-red-500/30">
              <span className="text-red-400 font-bold">noob Advice: </span>
              {activeIncidentPopup.topFix}
            </div>
          </div>

          {/* Quick Action Buttons */}
          <div className="flex items-center space-x-2 pt-0.5">
            <button
              onClick={() => {
                setIsOpen(true);
                setActiveTab('chat');
                setPopupDismissed(true);
              }}
              className="flex-1 py-1.5 px-2.5 rounded bg-gradient-to-r from-purple-700 to-indigo-600 hover:from-purple-600 hover:to-indigo-500 text-white font-bold text-[11px] flex items-center justify-center space-x-1.5 shadow transition"
            >
              <Bot className="w-3.5 h-3.5" />
              <span>Ask noob for Fix</span>
            </button>
            <button
              onClick={() => {
                navigate('/incidents');
                setPopupDismissed(true);
              }}
              className="py-1.5 px-2.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 hover:text-white text-[11px] transition"
            >
              Inspect
            </button>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* COLLAPSED FLOATING LAUNCHER PILL ("noob")                         */}
      {/* ------------------------------------------------------------------ */}
      {!isOpen ? (
        <button
          onClick={() => {
            setIsOpen(true);
            setPopupDismissed(true);
          }}
          className="group flex items-center space-x-2.5 px-3.5 sm:px-4 py-2 sm:py-2.5 rounded-full bg-slate-950/95 hover:bg-slate-900 border-2 border-purple-500/70 hover:border-purple-400 text-white shadow-[0_0_25px_rgba(168,85,247,0.45)] hover:shadow-[0_0_35px_rgba(168,85,247,0.7)] transition-all duration-300 transform hover:-translate-y-0.5 active:translate-y-0"
          title="Open noob AI Remediation Advisor"
        >
          <div className="relative">
            <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-full bg-gradient-to-tr from-purple-700 via-indigo-600 to-cyan-500 flex items-center justify-center text-white shadow-md">
              <Bot className="w-4 h-4 animate-bounce" />
            </div>
            <span className="absolute -top-0.5 -right-0.5 flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
            </span>
          </div>

          <div className="flex flex-col text-left">
            <div className="flex items-center space-x-1.5">
              <span className="text-xs sm:text-sm font-extrabold tracking-wider text-purple-300 group-hover:text-purple-200 uppercase">
                noob
              </span>
              <span className="text-[9px] sm:text-[10px] px-1.5 py-0.2 rounded bg-purple-950 border border-purple-500/40 text-purple-300 font-semibold">
                AI ADVISOR
              </span>
            </div>
            <span className="text-[9px] sm:text-[10px] text-slate-400">
              {activeIncidentPopup && !popupDismissed ? '⚠️ Incident Alert!' : 'Ask me anything'}
            </span>
          </div>

          <Sparkles className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-amber-400 group-hover:rotate-12 transition-transform ml-1" />
        </button>
      ) : (
        /* ------------------------------------------------------------------ */
        /* EXPANDED NOOB CHATBOT & REMEDIATION ADVISOR PANEL                 */
        /* ------------------------------------------------------------------ */
        <div className="w-[calc(100vw-1.5rem)] sm:w-[440px] md:w-[460px] h-[550px] max-h-[82vh] flex flex-col rounded-2xl bg-slate-950/98 border-2 border-purple-500/80 shadow-[0_0_50px_rgba(168,85,247,0.35)] backdrop-blur-2xl overflow-hidden animate-slide-in">
          {/* Chatbot Header */}
          <div className="p-3 sm:p-3.5 bg-gradient-to-r from-purple-950/90 via-slate-900 to-indigo-950/90 border-b border-purple-500/30 flex items-center justify-between">
            <div className="flex items-center space-x-2.5">
              <div className="w-8 h-8 rounded-xl bg-gradient-to-tr from-purple-600 to-indigo-500 flex items-center justify-center text-white shadow-md">
                <Bot className="w-4 h-4" />
              </div>
              <div>
                <div className="flex items-center space-x-2">
                  <span className="font-extrabold text-sm text-white tracking-wider">
                    noob
                  </span>
                  <span className="text-[10px] font-semibold text-purple-300 bg-purple-900/70 px-1.5 py-0.5 rounded border border-purple-500/40">
                    AI Remediation Advisor
                  </span>
                </div>
                <div className="text-[10px] text-amber-300/90 flex items-center gap-1 mt-0.5">
                  <Sparkles className="w-3 h-3 text-amber-400 shrink-0" />
                  <span className="truncate">AI suggestion, human review required</span>
                </div>
              </div>
            </div>

            <div className="flex items-center space-x-1.5">
              <button
                onClick={fetchAdvisory}
                disabled={loading}
                className="p-1.5 rounded-lg bg-slate-900/80 hover:bg-slate-800 text-slate-400 hover:text-white border border-slate-800 transition"
                title="Refresh playbook advisory"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              </button>
              <button
                onClick={() => setIsOpen(false)}
                className="p-1.5 rounded-lg bg-slate-900/80 hover:bg-red-950 text-slate-400 hover:text-red-300 border border-slate-800 hover:border-red-500/40 transition"
                title="Minimize noob"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Responsive Navigation Tabs */}
          <div className="flex items-center border-b border-slate-800 bg-slate-950/90 text-xs px-2 pt-1.5">
            <button
              onClick={() => setActiveTab('chat')}
              className={`flex-1 py-1.5 text-center font-bold border-b-2 transition-all flex items-center justify-center gap-1.5 ${
                activeTab === 'chat'
                  ? 'border-purple-400 text-purple-300 bg-purple-950/30'
                  : 'border-transparent text-slate-400 hover:text-slate-300'
              }`}
            >
              <MessageSquare className="w-3.5 h-3.5" />
              <span>Chat</span>
            </button>
            <button
              onClick={() => setActiveTab('fixes')}
              className={`flex-1 py-1.5 text-center font-bold border-b-2 transition-all flex items-center justify-center gap-1.5 ${
                activeTab === 'fixes'
                  ? 'border-purple-400 text-purple-300 bg-purple-950/30'
                  : 'border-transparent text-slate-400 hover:text-slate-300'
              }`}
            >
              <Wrench className="w-3.5 h-3.5" />
              <span>Fixes ({topFixes.length})</span>
            </button>
            <button
              onClick={() => setActiveTab('incidents')}
              className={`flex-1 py-1.5 text-center font-bold border-b-2 transition-all flex items-center justify-center gap-1.5 ${
                activeTab === 'incidents'
                  ? 'border-purple-400 text-purple-300 bg-purple-950/30'
                  : 'border-transparent text-slate-400 hover:text-slate-300'
              }`}
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>Threats ({incidents.length})</span>
            </button>
          </div>

          {/* -------------------------------------------------------------- */}
          {/* TAB 1: INTERACTIVE CHATBOT (Responsive Message Stream)         */}
          {/* -------------------------------------------------------------- */}
          {activeTab === 'chat' && (
            <div className="flex-1 flex flex-col min-h-0 bg-slate-950/80">
              {/* Message History */}
              <div ref={chatScrollRef} className="flex-1 overflow-y-auto p-3 space-y-3 text-xs">
                {chatMessages.map((msg) => (
                  <div
                    key={msg.id}
                    className={`flex flex-col ${msg.sender === 'user' ? 'items-end' : 'items-start'}`}
                  >
                    <div
                      className={`max-w-[88%] rounded-xl p-3 leading-relaxed whitespace-pre-wrap ${
                        msg.sender === 'user'
                          ? 'bg-purple-700 text-white rounded-br-none shadow'
                          : 'bg-slate-900/90 text-slate-200 border border-slate-800 rounded-bl-none shadow'
                      }`}
                    >
                      {msg.text}
                    </div>
                    <span className="text-[10px] text-slate-500 mt-1 px-1">
                      {msg.sender === 'user' ? 'You' : 'noob'} &bull; {msg.timestamp}
                    </span>

                    {/* Quick Pick Action Chips */}
                    {msg.quickPicks && msg.quickPicks.length > 0 && (
                      <div className="flex flex-wrap gap-1.5 mt-2 max-w-[95%]">
                        {msg.quickPicks.map((chip, idx) => (
                          <button
                            key={idx}
                            onClick={() => handleSendMessage(chip)}
                            className="text-[10px] py-1 px-2.5 rounded-full bg-purple-950/60 hover:bg-purple-900/90 text-purple-300 border border-purple-500/40 hover:border-purple-400 transition"
                          >
                            {chip}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>

              {/* Chat Input Bar */}
              <div className="p-2.5 bg-slate-950 border-t border-slate-800/90 flex items-center space-x-2">
                <input
                  type="text"
                  value={inputMessage}
                  onChange={(e) => setInputMessage(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleSendMessage()}
                  placeholder="Ask noob about incidents, fixes, or gateway..."
                  className="flex-1 bg-slate-900 border border-slate-700/80 focus:border-purple-400 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 outline-none transition"
                />
                <button
                  onClick={() => handleSendMessage()}
                  disabled={!inputMessage.trim()}
                  className="p-2 rounded-lg bg-purple-600 hover:bg-purple-500 disabled:opacity-40 text-white transition shadow"
                  title="Send message"
                >
                  <Send className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}

          {/* -------------------------------------------------------------- */}
          {/* TAB 2: RECOMMENDED PLAYBOOK FIXES                              */}
          {/* -------------------------------------------------------------- */}
          {activeTab === 'fixes' && (
            <div className="flex-1 overflow-y-auto p-3 space-y-2.5 text-xs">
              <div className="flex items-center justify-between text-[11px] text-slate-400 px-0.5">
                <span>Playbook fixes mapped from evidence</span>
                <span className="text-purple-400 font-semibold">{topFixes.length} Fixes Ready</span>
              </div>

              {topFixes.length > 0 ? (
                topFixes.map((fix, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded-lg bg-slate-900/90 border border-purple-500/20 hover:border-purple-500/50 transition space-y-1.5 group"
                  >
                    <div className="flex items-start space-x-2">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 mt-0.5 flex-shrink-0 group-hover:scale-110 transition-transform" />
                      <div className="flex-1 min-w-0">
                        <div className="text-white font-semibold text-[11px] leading-snug">
                          {fix.step}
                        </div>
                        <div className="text-[10px] text-slate-400 mt-0.5 line-clamp-2">
                          {fix.why}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center justify-between pt-1 border-t border-slate-800 text-[10px]">
                      <span className="text-purple-400 font-semibold truncate max-w-[200px]">
                        {fix.playbook_title || fix.playbook_id}
                      </span>
                      <button
                        onClick={() => {
                          setActiveTab('chat');
                          handleSendMessage(`Explain playbook step: "${fix.step}"`);
                        }}
                        className="text-cyan-400 hover:text-cyan-300 font-medium"
                      >
                        Ask noob &rarr;
                      </button>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-center py-10 text-slate-500 text-[11px]">
                  No immediate playbook fixes queued. Decoy boundaries secure.
                </div>
              )}
            </div>
          )}

          {/* -------------------------------------------------------------- */}
          {/* TAB 3: ACTIVE THREATS & INCIDENTS                              */}
          {/* -------------------------------------------------------------- */}
          {activeTab === 'incidents' && (
            <div className="flex-1 overflow-y-auto p-3 space-y-2 text-xs">
              <div className="text-[11px] text-slate-400 px-0.5">
                Select an incident to view full playbook walkthrough:
              </div>
              {incidents.length > 0 ? (
                incidents.slice(0, 6).map((inc) => (
                  <div
                    key={inc.id}
                    onClick={() => {
                      navigate('/incidents');
                      setIsOpen(false);
                    }}
                    className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-red-500/50 cursor-pointer transition space-y-1"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-white font-semibold truncate text-[11px] max-w-[230px]">
                        {inc.title}
                      </span>
                      <span
                        className={`text-[10px] font-bold uppercase px-1.5 py-0.2 rounded border ${
                          inc.severity === 'critical'
                            ? 'bg-red-950 text-red-300 border-red-500/40'
                            : 'bg-amber-950 text-amber-300 border-amber-500/40'
                        }`}
                      >
                        {inc.priority || inc.severity || 'CRITICAL'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-[10px] text-slate-400">
                      <span>Incident INC-{inc.id}</span>
                      <span className="text-purple-400 flex items-center gap-0.5">
                        Inspect Advisory &rarr;
                      </span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-center py-10 text-slate-500 text-[11px]">
                  No active incident tickets.
                </div>
              )}
            </div>
          )}

          {/* Footer Navigation Shortcuts */}
          <div className="p-2 sm:p-2.5 bg-slate-950 border-t border-slate-800 flex items-center justify-between text-xs">
            <button
              onClick={() => {
                navigate('/failures');
                setIsOpen(false);
              }}
              className="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-700/60 transition flex items-center gap-1 text-[11px]"
            >
              <Zap className="w-3 h-3 text-amber-400" />
              <span>Gateway Watch</span>
            </button>
            <button
              onClick={() => {
                navigate('/incidents');
                setIsOpen(false);
              }}
              className="px-3 py-1 rounded-lg bg-purple-700 hover:bg-purple-600 text-white font-bold transition flex items-center gap-1 text-[11px] shadow-sm"
            >
              <span>Incident Queue</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
