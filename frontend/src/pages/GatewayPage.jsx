import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  ShieldAlert,
  Server,
  Activity,
  ArrowRight,
  TrendingUp,
  Play,
  Pause,
  RotateCcw,
  CheckCircle,
  CheckCircle2,
  Square,
  AlertOctagon,
  RefreshCw,
  Copy,
  ExternalLink,
  Lock,
  Layers,
  Zap,
  UserCheck,
  ChevronRight,
  Info,
  X,
  AlertTriangle,
  Search,
  Filter,
  Eye,
  Sliders,
  ShieldCheck,
  History,
  FastForward,
  Flame,
  Radio,
  FileCode,
  Key,
  ShieldX,
  Target,
  Clock,
  Hourglass,
  Database,
  Sparkles,
} from 'lucide-react';
import { useSoc } from '../context/SocContext';
import { api } from '../api/client';
import GatewayLifecyclePanel from '../components/GatewayLifecyclePanel';

export default function GatewayPage() {
  const {
    addToast,
    latestRiskScoreUpdate,
    latestSessionTransition,
    sessionTransitions = [],
    latestDecoyInteraction,
    decoyInteractions = [],
  } = useSoc();
  const [stats, setStats] = useState(null);
  const [sessions, setSessions] = useState([]);
  const [pointAllocations, setPointAllocations] = useState({});
  const [selectedSession, setSelectedSession] = useState(null);
  const [sessionDetail, setSessionDetail] = useState(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [loading, setLoading] = useState(true);
  const [nginxConfig, setNginxConfig] = useState('');
  const [showConfig, setShowConfig] = useState(false);
  const [showAllocations, setShowAllocations] = useState(false);

  // Filters for sessions table
  const [searchQuery, setSearchQuery] = useState('');
  const [classificationFilter, setClassificationFilter] = useState('ALL');
  const [routeFilter, setRouteFilter] = useState('ALL');

  // Decoy Latency & Attacker Observation state
  const [decoyStats, setDecoyStats] = useState(null);
  const [decoyLatencyMode, setDecoyLatencyMode] = useState('controlled');
  const [comparisonCategory, setComparisonCategory] = useState('auth_login');
  const [comparisonResult, setComparisonResult] = useState(null);
  const [runningComparison, setRunningComparison] = useState(false);
  const [showDecoyObservation, setShowDecoyObservation] = useState(true);

  // Single manual simulator state
  const [simIp, setSimIp] = useState('203.0.113.88');
  const [simPath, setSimPath] = useState('/auth/login');
  const [simMethod, setSimMethod] = useState('POST');
  const [simResult, setSimResult] = useState(null);
  const [simulating, setSimulating] = useState(false);

  // ==========================================
  // HACKATHON LIVE ATTACK DEMONSTRATION ENGINE
  // ==========================================
  const [selectedScenarioKey, setSelectedScenarioKey] = useState('multivector_apt');
  const [demoSpeed, setDemoSpeed] = useState('fast'); // 'fast' (~30s), 'normal' (~55s), 'step'
  const [demoRunning, setDemoRunning] = useState(false);
  const [demoPaused, setDemoPaused] = useState(false);
  const [demoExecuting, setDemoExecuting] = useState(false);
  const [demoCurrentStepIndex, setDemoCurrentStepIndex] = useState(0);
  const [demoEventsLog, setDemoEventsLog] = useState([]);
  const [demoSessionState, setDemoSessionState] = useState(null);
  const [demoTransitionAlert, setDemoTransitionAlert] = useState(null);
  const [demoLastResponse, setDemoLastResponse] = useState(null);
  const [demoStepError, setDemoStepError] = useState(null);

  const demoTimerRef = useRef(null);
  const demoRunningRef = useRef(false);
  demoRunningRef.current = demoRunning;
  const demoPausedRef = useRef(false);
  demoPausedRef.current = demoPaused;
  const demoSpeedRef = useRef('fast');
  demoSpeedRef.current = demoSpeed;
  const isExecutingRef = useRef(false);
  const currentScenarioRef = useRef(null);

  // Scenario Definitions
  const SCENARIOS = useMemo(
    () => ({
      normal_visitor: {
        id: 'normal_visitor',
        title: 'Normal Visitor',
        sessionId: 'demo_sess_normal_alice',
        ip: '198.51.100.12',
        account: 'alice@legitimate-corp.com',
        description: 'Benign browsing pattern: product catalog exploration, successful authentication, and profile access. Stays score 0.',
        steps: [
          {
            label: 'Home page landing and asset loading',
            category: 'abnormal_rate',
            endpoint: '/',
            method: 'GET',
            eventType: 'page_view',
            evidence: 'Standard browser request with normal HTTP headers and CSS assets',
          },
          {
            label: 'Browse product catalog',
            category: 'endpoint_enumeration',
            endpoint: '/api/products/catalog',
            method: 'GET',
            eventType: 'api_read',
            evidence: 'Standard catalog pagination request',
          },
          {
            label: 'Submit legitimate user credentials',
            category: 'login_failures',
            endpoint: '/api/auth/login',
            method: 'POST',
            eventType: 'auth_success',
            evidence: 'User alice@legitimate-corp.com authenticated successfully',
          },
          {
            label: 'Load customer overview dashboard',
            category: 'database_access',
            endpoint: '/api/user/dashboard',
            method: 'GET',
            eventType: 'dashboard_load',
            evidence: 'Authorized profile view with valid session token',
          },
          {
            label: 'Check user billing and order history',
            category: 'payment_manipulation',
            endpoint: '/api/billing/history',
            method: 'GET',
            eventType: 'order_history',
            evidence: 'Normal read query for user order invoices',
          },
        ],
      },
      login_brute_force: {
        id: 'login_brute_force',
        title: 'Brute-Force Login Attack',
        sessionId: 'demo_sess_brute_force_bob',
        ip: '198.51.100.45',
        account: 'admin@target-corp.com',
        description: 'Repetitive authentication credential stuffing. Demonstrates attempt-multiplier point accumulation on auth endpoints.',
        steps: [
          {
            label: 'First failed login attempt',
            category: 'login_failures',
            endpoint: '/auth/login',
            method: 'POST',
            eventType: 'auth_failure',
            evidence: 'Failed login attempt 1: user admin password [wrong]',
          },
          {
            label: 'Second failed login attempt',
            category: 'login_failures',
            endpoint: '/auth/login',
            method: 'POST',
            eventType: 'auth_failure',
            evidence: 'Failed login attempt 2: rapid retry within 1.2s',
          },
          {
            label: 'Third failed login attempt',
            category: 'login_failures',
            endpoint: '/auth/login',
            method: 'POST',
            eventType: 'auth_failure',
            evidence: 'Failed login attempt 3: credential stuffing signature matched',
          },
          {
            label: 'Fourth failed login attempt with admin credential',
            category: 'login_failures',
            endpoint: '/auth/login',
            method: 'POST',
            eventType: 'auth_failure',
            evidence: 'Failed login attempt 4: dictionary attack pattern detected',
          },
          {
            label: 'Fifth failed login attempt - crossing threshold',
            category: 'login_failures',
            endpoint: '/auth/login',
            method: 'POST',
            eventType: 'auth_failure',
            evidence: 'Burst authentication failure threshold reached',
          },
        ],
      },
      otp_mfa_brute_force: {
        id: 'otp_mfa_brute_force',
        title: 'OTP / MFA Guessing Attack',
        sessionId: 'demo_sess_otp_guess_charlie',
        ip: '198.51.100.77',
        account: 'ceo@target-corp.com',
        description: 'Rapid OTP code verification guessing sequence. Triggers independent auth factor penalty and crosses diversion boundary.',
        steps: [
          {
            label: 'Initial login with stolen password',
            category: 'login_failures',
            endpoint: '/auth/login',
            method: 'POST',
            eventType: 'auth_step1',
            evidence: 'Password matched, prompted for 6-digit MFA OTP code',
          },
          {
            label: 'Submit guessed OTP: 123456',
            category: 'otp_failures',
            endpoint: '/auth/otp/verify',
            method: 'POST',
            eventType: 'otp_failure',
            evidence: 'Invalid OTP code 123456 for ceo@target-corp.com',
          },
          {
            label: 'Submit guessed OTP: 000000',
            category: 'otp_failures',
            endpoint: '/auth/otp/verify',
            method: 'POST',
            eventType: 'otp_failure',
            evidence: 'Invalid OTP code 000000; attempt 2 within 2 seconds',
          },
          {
            label: 'Submit guessed OTP: 111111',
            category: 'otp_failures',
            endpoint: '/auth/otp/verify',
            method: 'POST',
            eventType: 'otp_failure',
            evidence: 'Invalid OTP code 111111; rapid automated submission',
          },
          {
            label: 'Submit guessed OTP: 999999 - Triggers Diversion',
            category: 'otp_failures',
            endpoint: '/auth/otp/verify',
            method: 'POST',
            eventType: 'otp_failure',
            evidence: 'OTP brute force threshold exceeded. Session marked for isolation.',
          },
        ],
      },
      recon_config_scan: {
        id: 'recon_config_scan',
        title: 'Recon & Config Scanning',
        sessionId: 'demo_sess_recon_scanner',
        ip: '198.51.100.104',
        account: null,
        description: 'Automated vulnerability scanner probing sensitive paths (.env, .git, admin). Crosses 2 independent categories.',
        steps: [
          {
            label: 'Probe for exposed .env secrets file',
            category: 'secrets_probing',
            endpoint: '/.env',
            method: 'GET',
            eventType: 'path_probe',
            evidence: 'Direct request for environment secrets file /.env',
          },
          {
            label: 'Probe for exposed .git configuration repository',
            category: 'secrets_probing',
            endpoint: '/.git/config',
            method: 'GET',
            eventType: 'path_probe',
            evidence: 'Direct request for Git internal configuration',
          },
          {
            label: 'Scan administrative console endpoint',
            category: 'admin_path_probing',
            endpoint: '/admin/system',
            method: 'GET',
            eventType: 'admin_probe',
            evidence: 'Unauthorized probe to /admin/system without session',
          },
          {
            label: 'Scan internal debug configuration',
            category: 'admin_path_probing',
            endpoint: '/debug/vars',
            method: 'GET',
            eventType: 'admin_probe',
            evidence: 'Unauthorized request to /debug/vars profiling endpoint',
          },
          {
            label: 'Enumerate SQL API dump - Instant Diversion',
            category: 'endpoint_enumeration',
            endpoint: '/api/v1/dump/users',
            method: 'GET',
            eventType: 'enum_scan',
            evidence: 'Database enumeration tool signature detected',
          },
        ],
      },
      multivector_apt: {
        id: 'multivector_apt',
        title: 'Combined Multi-Vector Attack',
        sessionId: 'demo_sess_multivector_apt_target',
        ip: '198.51.100.199',
        account: 'target_admin@enterprise.internal',
        description: 'Complete multi-phase APT attack: Rate abuse → Login brute force → OTP guessing → Admin probe → Instant Real-to-Decoy transition.',
        steps: [
          {
            label: 'Step 1: Rapid API sweeping (Abnormal Rate)',
            category: 'abnormal_rate',
            endpoint: '/api/v1/ping',
            method: 'GET',
            eventType: 'rate_burst',
            evidence: '35 automated ping requests inside 500ms window',
          },
          {
            label: 'Step 2: Credential stuffing (Login Failures)',
            category: 'login_failures',
            endpoint: '/auth/login',
            method: 'POST',
            eventType: 'auth_failure',
            evidence: 'Repeated failed login attempts for administrator accounts',
          },
          {
            label: 'Step 3: OTP brute-force submission (OTP Failures)',
            category: 'otp_failures',
            endpoint: '/auth/otp/verify',
            method: 'POST',
            eventType: 'otp_failure',
            evidence: 'Automated permutations of MFA verification token',
          },
          {
            label: 'Step 4: Probe administrative privileged console (Admin Path)',
            category: 'admin_path_probing',
            endpoint: '/admin/config',
            method: 'GET',
            eventType: 'admin_probe',
            evidence: 'Unauthorized administrative route probing',
          },
          {
            label: 'Step 5: Attempt secrets file theft & DB injection (DIVERSION TRIGGER)',
            category: 'secrets_probing',
            endpoint: '/.env',
            method: 'GET',
            eventType: 'critical_breach',
            evidence: 'Immediate diversion rule triggered: Session permanently shifted to Decoy container',
          },
        ],
      },
    }),
    []
  );

  const currentScenario = SCENARIOS[selectedScenarioKey] || SCENARIOS.multivector_apt;
  currentScenarioRef.current = currentScenario;

  const defaultAllocations = {
    abnormal_rate: { label: 'Abnormal Rate / Burst Requests', max: 15.0 },
    login_failures: { label: 'Authentication / Login Failures', max: 20.0 },
    otp_failures: { label: 'Two-Factor / OTP Verification Failures', max: 15.0 },
    admin_path_probing: { label: 'Admin Path & Privileged Probing', max: 15.0 },
    secrets_probing: { label: 'Secrets & Configuration Probing (.env, .git)', max: 20.0 },
    endpoint_enumeration: { label: 'Endpoint Enumeration & Wordlist Scans', max: 10.0 },
    payment_manipulation: { label: 'Payment Gateway / Price Tampering', max: 20.0 },
    database_access: { label: 'Unauthorized Database Endpoints & Queries', max: 15.0 },
    unusual_time: { label: 'Temporal Off-Hours & Anomaly Multipliers', max: 5.0 },
  };

  const fetchGatewayData = async () => {
    try {
      setLoading(true);
      const [statsRes, sessionsRes, allocationsRes, nginxRes, decoyRes] = await Promise.allSettled([
        api.getGatewayStats(),
        api.getGatewaySessions(),
        api.getPointAllocations(),
        api.getNginxConfig(),
        api.getDecoyLatencyStats ? api.getDecoyLatencyStats() : Promise.resolve(null),
      ]);

      if (statsRes.status === 'fulfilled') setStats(statsRes.value);
      if (sessionsRes.status === 'fulfilled') setSessions(sessionsRes.value || []);
      if (allocationsRes.status === 'fulfilled') setPointAllocations(allocationsRes.value || {});
      if (nginxRes.status === 'fulfilled') setNginxConfig(nginxRes.value?.nginx_conf || '');
      if (decoyRes.status === 'fulfilled' && decoyRes.value) {
        setDecoyStats(decoyRes.value);
        if (decoyRes.value.latency_mode) {
          setDecoyLatencyMode(decoyRes.value.latency_mode);
        }
      }
    } catch (err) {
      console.error('Failed to load gateway telemetry:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGatewayData();
    const interval = setInterval(fetchGatewayData, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleInspectSession = async (sess) => {
    try {
      setSelectedSession(sess);
      setLoadingDetail(true);
      const detail = await api.getGatewaySessionDetail(sess.session_id);
      setSessionDetail(detail);
    } catch (err) {
      addToast(`Failed to load session details: ${err.message}`, 'error');
    } finally {
      setLoadingDetail(false);
    }
  };

  const handleSimulate = async () => {
    try {
      setSimulating(true);
      const res = await api.simulateGatewayDecision({
        src_ip: simIp,
        path: simPath,
        method: simMethod,
      });
      setSimResult(res);
      addToast(`Decision: ${res.routed_to.toUpperCase()} (Score: ${res.risk_score.toFixed(1)})`, 'info');
      await fetchGatewayData();
    } catch (err) {
      addToast(`Simulation failed: ${err.message}`, 'error');
    } finally {
      setSimulating(false);
    }
  };

  const handleResetVisitor = async () => {
    try {
      await api.resetGatewayVisitor(simIp);
      setSimResult(null);
      addToast(`Session & risk reset to 0 for IP: ${simIp}`, 'success');
      await fetchGatewayData();
    } catch (err) {
      addToast(`Reset failed: ${err.message}`, 'error');
    }
  };

  const handleToggleDecoyLatencyMode = async () => {
    const nextMode = decoyLatencyMode === 'controlled' ? 'normal' : 'controlled';
    try {
      await api.setDecoyLatencyMode(nextMode);
      setDecoyLatencyMode(nextMode);
      addToast(`Decoy Latency Mode switched to ${nextMode.toUpperCase()}`, 'success');
      if (api.getDecoyLatencyStats) {
        const dStats = await api.getDecoyLatencyStats();
        setDecoyStats(dStats);
      }
    } catch (err) {
      addToast(`Failed to toggle latency mode: ${err.message}`, 'error');
    }
  };

  const handleRunComparisonDemo = async () => {
    try {
      setRunningComparison(true);
      const res = await api.runDecoyLatencyComparison(comparisonCategory);
      setComparisonResult(res);
      addToast(`Latency measured: Normal ${res.normal_mode.measured_response_ms.toFixed(0)}ms vs Controlled ${res.controlled_mode.measured_response_ms.toFixed(0)}ms (${res.observation_benefit.time_dilation_factor}x)`, 'info');
    } catch (err) {
      addToast(`Comparison failed: ${err.message}`, 'error');
    } finally {
      setRunningComparison(false);
    }
  };

  const copyConfig = () => {
    navigator.clipboard.writeText(nginxConfig);
    addToast('NGINX configuration copied to clipboard', 'success');
  };

  // Execution delay based on speed
  const getStepDelay = (speed) => {
    switch (speed) {
      case 'fast':
        return 1800; // ~30s for 5 steps
      case 'normal':
      case 'standard':
        return 4200; // ~55s for 5 steps
      default:
        return 2000;
    }
  };

  const handleSpeedChange = (newSpeed) => {
    setDemoSpeed(newSpeed);
    demoSpeedRef.current = newSpeed;
    addToast(`Execution speed changed to ${newSpeed.toUpperCase()}`, 'info');
  };

  const executeScenarioStep = async (stepIndex) => {
    const scenario = currentScenarioRef.current;
    if (!scenario || stepIndex >= scenario.steps.length) return false;

    const step = scenario.steps[stepIndex];
    isExecutingRef.current = true;
    setDemoExecuting(true);
    setDemoStepError(null);

    try {
      const payload = {
        session_id: scenario.sessionId,
        src_ip: scenario.ip,
        account_email: scenario.account,
        category: step.category,
        endpoint: step.endpoint,
        method: step.method,
        event_type: step.eventType,
        evidence: step.evidence,
      };

      const res = await api.executeDemoStep(payload);
      setDemoLastResponse(res);
      setDemoSessionState(res);

      const logItem = {
        stepIndex: stepIndex + 1,
        label: step.label,
        category: step.category,
        endpoint: step.endpoint,
        previousScore: res.previous_risk_score,
        newScore: res.risk_score,
        classification: res.risk_classification,
        isDiverted: res.is_diverted,
        currentRoute: res.current_route,
        transitionTriggered: res.transition_triggered,
        timestamp: new Date().toLocaleTimeString(),
      };

      setDemoEventsLog((prev) => [logItem, ...prev]);

      if (res.transition_triggered && !demoTransitionAlert) {
        setDemoTransitionAlert({
          session_id: scenario.sessionId,
          src_ip: scenario.ip,
          triggering_event: step.label,
          previous_score: res.previous_risk_score,
          new_score: res.risk_score,
          reason: res.diversion_reason || 'Cumulative threshold and independent categories reached',
          timestamp: new Date().toLocaleTimeString(),
        });
      }

      setDemoCurrentStepIndex(stepIndex + 1);
      fetchGatewayData();
      return true;
    } catch (err) {
      console.error('Failed step execution:', err);
      setDemoStepError(`Error executing step ${stepIndex + 1}: ${err.message}`);
      return false;
    } finally {
      isExecutingRef.current = false;
      setDemoExecuting(false);
    }
  };

  const scheduleNextStep = (nextIndex) => {
    if (!demoRunningRef.current || demoPausedRef.current) return;
    const scenario = currentScenarioRef.current;
    if (!scenario || nextIndex >= scenario.steps.length) {
      setDemoRunning(false);
      demoRunningRef.current = false;
      addToast('Scenario complete: All sequential steps executed.', 'success');
      return;
    }

    if (demoSpeedRef.current === 'step') {
      return;
    }

    const delay = getStepDelay(demoSpeedRef.current);
    demoTimerRef.current = setTimeout(async () => {
      if (!demoRunningRef.current || demoPausedRef.current) return;
      const ok = await executeScenarioStep(nextIndex);
      if (ok) {
        scheduleNextStep(nextIndex + 1);
      } else {
        setDemoPaused(true);
        demoPausedRef.current = true;
      }
    }, delay);
  };

  const handleRunScenario = async () => {
    if (demoTimerRef.current) {
      clearTimeout(demoTimerRef.current);
      demoTimerRef.current = null;
    }

    setDemoRunning(true);
    demoRunningRef.current = true;
    setDemoPaused(false);
    demoPausedRef.current = false;

    let startIndex = demoCurrentStepIndex;
    if (startIndex >= currentScenario.steps.length) {
      startIndex = 0;
      setDemoCurrentStepIndex(0);
      setDemoEventsLog([]);
      setDemoTransitionAlert(null);
    }

    const ok = await executeScenarioStep(startIndex);
    if (ok) {
      scheduleNextStep(startIndex + 1);
    }
  };

  const handlePause = () => {
    if (demoTimerRef.current) {
      clearTimeout(demoTimerRef.current);
      demoTimerRef.current = null;
    }
    setDemoPaused(true);
    demoPausedRef.current = true;
    addToast('Simulation execution paused.', 'info');
  };

  const handleResume = () => {
    setDemoPaused(false);
    demoPausedRef.current = false;
    addToast('Simulation execution resumed.', 'info');
    scheduleNextStep(demoCurrentStepIndex);
  };

  const handleStop = () => {
    if (demoTimerRef.current) {
      clearTimeout(demoTimerRef.current);
      demoTimerRef.current = null;
    }
    setDemoRunning(false);
    demoRunningRef.current = false;
    setDemoPaused(false);
    demoPausedRef.current = false;
    addToast('Simulation halted.', 'info');
  };

  const handleRestartScenario = () => {
    if (demoTimerRef.current) {
      clearTimeout(demoTimerRef.current);
      demoTimerRef.current = null;
    }
    setDemoRunning(false);
    demoRunningRef.current = false;
    setDemoPaused(false);
    demoPausedRef.current = false;
    setDemoCurrentStepIndex(0);
    setDemoEventsLog([]);
    setDemoTransitionAlert(null);
    setDemoLastResponse(null);
    setDemoStepError(null);
    addToast('Scenario reset to Step 1.', 'info');
  };

  const handleManualNextStep = async () => {
    if (isExecutingRef.current) return;
    if (demoCurrentStepIndex >= currentScenario.steps.length) {
      addToast('All scenario steps have already executed.', 'warning');
      return;
    }
    await executeScenarioStep(demoCurrentStepIndex);
  };

  const handleResetDemoSession = async () => {
    if (demoTimerRef.current) {
      clearTimeout(demoTimerRef.current);
      demoTimerRef.current = null;
    }
    setDemoRunning(false);
    demoRunningRef.current = false;
    setDemoPaused(false);
    demoPausedRef.current = false;

    try {
      await api.resetDemoSession(currentScenario.sessionId);
      setDemoCurrentStepIndex(0);
      setDemoEventsLog([]);
      setDemoSessionState(null);
      setDemoTransitionAlert(null);
      setDemoLastResponse(null);
      setDemoStepError(null);
      addToast(`Session ${currentScenario.sessionId} purged and reset to 0.`, 'success');
      await fetchGatewayData();
    } catch (err) {
      addToast(`Failed to reset demo session: ${err.message}`, 'error');
    }
  };

  // Filter sessions
  const filteredSessions = useMemo(() => {
    return sessions.filter((sess) => {
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const matches =
          (sess.session_id && sess.session_id.toLowerCase().includes(q)) ||
          (sess.src_ip && sess.src_ip.toLowerCase().includes(q)) ||
          (sess.account_email && sess.account_email.toLowerCase().includes(q));
        if (!matches) return false;
      }
      if (classificationFilter !== 'ALL') {
        if (sess.risk_classification !== classificationFilter) return false;
      }
      if (routeFilter !== 'ALL') {
        const route = sess.is_diverted || sess.current_route === 'decoy' ? 'DECOY' : 'REAL';
        if (route !== routeFilter) return false;
      }
      return true;
    });
  }, [sessions, searchQuery, classificationFilter, routeFilter]);

  const getClassificationBadge = (cls) => {
    switch (cls) {
      case 'LIKELY_MALICIOUS':
        return 'bg-rose-950/60 text-rose-300 border-rose-800';
      case 'HIGH_RISK':
        return 'bg-orange-950/60 text-orange-300 border-orange-800';
      case 'SUSPICIOUS':
        return 'bg-amber-950/60 text-amber-300 border-amber-800';
      default:
        return 'bg-emerald-950/60 text-emerald-300 border-emerald-800';
    }
  };

  const getScoreColor = (score) => {
    if (score < 30) return 'text-emerald-400';
    if (score < 50) return 'text-amber-400';
    if (score < 70) return 'text-orange-400';
    return 'text-rose-400';
  };

  const getScoreBarBg = (score) => {
    if (score < 30) return 'bg-emerald-500';
    if (score < 50) return 'bg-amber-500';
    if (score < 70) return 'bg-orange-500';
    return 'bg-rose-500';
  };

  return (
    <div className="space-y-4 font-sans text-slate-300 pb-12">
      {/* ================================================================== */}
      {/* 1. GATEWAY LIFECYCLE & HARDENING (COMPACT 3-COLUMN)                */}
      {/* ================================================================== */}
      <GatewayLifecyclePanel />

      {/* ================================================================== */}
      {/* 2. RISK SCORING HEADER & CONTROLS                                  */}
      {/* ================================================================== */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div>
          <h1 className="text-base font-semibold text-slate-100 tracking-wide font-mono">
            Deception Gateway & Risk Scoring
          </h1>
          <p className="text-xs text-slate-400 mt-0.5 font-mono">
            Real-time behavioural analysis and intelligent traffic diversion.
          </p>
        </div>

        <div className="flex items-center space-x-2 font-mono text-xs">
          <button
            onClick={() => setShowAllocations(!showAllocations)}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-white rounded transition"
          >
            <Sliders className="w-3.5 h-3.5" />
            <span>{showAllocations ? 'Hide Model' : 'Point Model (100 pts)'}</span>
          </button>
          <button
            onClick={() => setShowConfig(!showConfig)}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-white rounded transition"
          >
            <Layers className="w-3.5 h-3.5" />
            <span>{showConfig ? 'Hide NGINX' : 'NGINX Config'}</span>
          </button>
          <button
            onClick={fetchGatewayData}
            className="p-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-white rounded transition"
            title="Refresh Gateway Telemetry"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Point Allocation Reference Card (Expandable) */}
      {showAllocations && (
        <div className="rounded-lg bg-slate-900/80 border border-slate-800 p-4 font-mono text-xs space-y-3 shadow-sm">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <span className="text-slate-200 font-semibold flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              0–100 Behaviour Point Allocation & Threshold Reference
            </span>
            <span className="text-[11px] text-slate-500">Max Cumulative = 100.0 Pts</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
            {Object.entries(defaultAllocations).map(([k, item]) => {
              const maxVal = pointAllocations[k] !== undefined ? pointAllocations[k] : item.max;
              return (
                <div key={k} className="p-2.5 bg-slate-950 border border-slate-800 rounded flex justify-between items-center">
                  <div className="min-w-0 pr-2">
                    <div className="text-slate-200 font-medium truncate">{item.label}</div>
                    <div className="text-[10px] text-slate-500 uppercase">{k}</div>
                  </div>
                  <div className="text-right shrink-0">
                    <span className="text-xs font-bold text-slate-100">{maxVal}</span>
                    <span className="text-[9px] text-slate-500 block">max pts</span>
                  </div>
                </div>
              );
            })}
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 pt-2 border-t border-slate-800 text-[11px]">
            <div className="p-2 bg-emerald-950/40 border border-emerald-800/60 rounded text-emerald-300">
              <span className="font-bold">0 – 29: NORMAL</span>
              <div className="text-[10px] text-slate-400">Real App (Trusted)</div>
            </div>
            <div className="p-2 bg-amber-950/40 border border-amber-800/60 rounded text-amber-300">
              <span className="font-bold">30 – 49: SUSPICIOUS</span>
              <div className="text-[10px] text-slate-400">Real App (Enhanced Monitoring)</div>
            </div>
            <div className="p-2 bg-orange-950/40 border border-orange-800/60 rounded text-orange-300">
              <span className="font-bold">50 – 69: HIGH_RISK</span>
              <div className="text-[10px] text-slate-400">Real App (Scrutiny / Alert)</div>
            </div>
            <div className="p-2 bg-rose-950/40 border border-rose-800/60 rounded text-rose-300">
              <span className="font-bold">70 – 100: LIKELY_MALICIOUS</span>
              <div className="text-[10px] text-slate-400">Decoy (Req. &ge; 2 categories)</div>
            </div>
          </div>
        </div>
      )}

      {/* NGINX Config Viewer Modal (Expandable) */}
      {showConfig && (
        <div className="rounded-lg bg-slate-900/80 border border-slate-800 p-4 font-mono text-xs space-y-3 shadow-sm">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <span className="text-slate-200 font-semibold flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              Production NGINX Reverse-Proxy Configuration
            </span>
            <button
              onClick={copyConfig}
              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 flex items-center gap-1.5 transition"
            >
              <Copy className="w-3.5 h-3.5" />
              <span>Copy Config</span>
            </button>
          </div>
          <pre className="p-3 bg-slate-950 border border-slate-800 rounded text-slate-300 font-mono text-[11px] overflow-x-auto max-h-56 leading-relaxed">
            {nginxConfig || '# Loading NGINX configuration snippet...'}
          </pre>
        </div>
      )}

      {/* ================================================================== */}
      {/* 3. FOUR COMPACT GATEWAY KPI CARDS                                  */}
      {/* ================================================================== */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>TOTAL REQUESTS</span>
            <Activity className="w-3.5 h-3.5 text-slate-400" />
          </div>
          <div className="flex items-baseline justify-between pt-1 font-mono">
            <span className="text-2xl font-bold text-slate-100">{stats?.total_requests || 0}</span>
            <span className="text-[10px] text-slate-500">Proxied Volume</span>
          </div>
        </div>

        <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>REAL APP TRAFFIC</span>
            <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="flex items-baseline justify-between pt-1 font-mono">
            <span className="text-2xl font-bold text-emerald-400">{stats?.real_traffic_count || 0}</span>
            <span className="text-[10px] text-slate-500">Score 0 – 69</span>
          </div>
        </div>

        <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>DECOY TRAFFIC (DIVERTED)</span>
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="flex items-baseline justify-between pt-1 font-mono">
            <span className="text-2xl font-bold text-rose-400">{stats?.decoy_traffic_count || 0}</span>
            <span className="text-[10px] text-slate-500">Trapped Honeynet</span>
          </div>
        </div>

        <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>ACTIVE SESSIONS</span>
            <UserCheck className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="flex items-baseline justify-between pt-1 font-mono">
            <span className="text-2xl font-bold text-amber-300">{sessions.length}</span>
            <span className="text-[10px] text-slate-500">Tracked Visitors</span>
          </div>
        </div>
      </div>

      {/* ================================================================== */}
      {/* 4. REAL-TO-DECOY DIVERSIONS (COMPACT STREAM)                       */}
      {/* ================================================================== */}
      <div className="rounded-lg bg-slate-900/60 border border-slate-800 p-3.5 space-y-3 font-mono">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-2">
          <div className="flex items-center space-x-2">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <h2 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
              Real-to-Decoy Session Diversions
            </h2>
          </div>
          <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
            {sessionTransitions.length} Diversions Recorded
          </span>
        </div>

        {sessionTransitions.length === 0 ? (
          <div className="py-5 text-center text-xs text-slate-500 font-mono">
            Zero real-to-decoy diversions recorded in current session. Perimeter traps armed.
          </div>
        ) : (
          <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
            {sessionTransitions.map((tr, idx) => (
              <div
                key={idx}
                className="p-2.5 rounded bg-slate-950/70 border border-slate-800 hover:border-slate-700 text-xs flex flex-col md:flex-row md:items-center justify-between gap-2.5 transition"
              >
                <div className="space-y-1 min-w-0">
                  <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                    <span className="font-bold text-slate-100 truncate">{tr.session_id}</span>
                    <span className="text-slate-500 text-[11px]">({tr.src_ip})</span>
                    <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-emerald-950/60 border border-emerald-800 text-emerald-400">
                      REAL
                    </span>
                    <ArrowRight className="w-3 h-3 text-slate-400" />
                    <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-rose-950/60 border border-rose-800 text-rose-300">
                      DECOY
                    </span>
                    <span className="px-1.5 py-0.2 rounded text-[10px] uppercase font-bold border bg-rose-950/40 text-rose-400 border-rose-800">
                      {tr.severity || 'CRITICAL'}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 truncate">
                    <strong className="text-amber-400 mr-1">{tr.triggering_event || tr.triggering_category || 'Malicious Trigger'}:</strong>
                    <span>{tr.reason}</span>
                  </div>
                </div>

                <div className="flex items-center space-x-3 shrink-0 text-right">
                  <div>
                    <div className="text-[11px] font-bold text-slate-200">
                      Score: <span className="text-slate-400">{tr.previous_score ?? 0}</span> &rarr; <span className="text-rose-400">{tr.new_score}</span>
                    </div>
                    <div className="text-[10px] text-slate-500">
                      {tr.timestamp ? new Date(tr.timestamp).toLocaleTimeString() : 'Recent'}
                    </div>
                  </div>
                  <button
                    onClick={() => handleInspectSession({ session_id: tr.session_id, src_ip: tr.src_ip })}
                    className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded border border-slate-700 text-[10px] font-bold flex items-center gap-1 transition"
                  >
                    <Eye className="w-3 h-3" />
                    <span>Inspect</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ================================================================== */}
      {/* 5. CONTROLLED ATTACK SIMULATOR (COMPACT PANEL)                    */}
      {/* ================================================================== */}
      <div className="rounded-lg bg-slate-900/60 border border-slate-800 p-4 font-mono space-y-3.5 shadow-sm">
        {/* Simulator Header & Speed Selector */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 border-b border-slate-800 pb-2.5">
          <div>
            <div className="flex items-center space-x-2">
              <Flame className="w-4 h-4 text-amber-400" />
              <h2 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                Controlled Attack Simulator
              </h2>
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Progression: <span className="text-emerald-400">NORMAL</span> &rarr; <span className="text-amber-400">SUSPICIOUS</span> &rarr; <span className="text-orange-400">HIGH RISK</span> &rarr; <span className="text-rose-400">LIKELY MALICIOUS</span> &rarr; <span className="text-rose-300 font-bold">REAL-TO-DECOY</span>
            </p>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {/* Speed & Mode Selector */}
            <div className="flex items-center bg-slate-950 border border-slate-800 rounded p-0.5 text-xs">
              <span className="text-[11px] text-slate-500 px-1.5 flex items-center gap-1">
                <FastForward className="w-3 h-3 text-cyan-400" />
                Speed:
              </span>
              {[
                { id: 'fast', label: 'Fast (30s)' },
                { id: 'normal', label: 'Normal (55s)' },
                { id: 'step', label: 'Manual Step' },
              ].map((sp) => (
                <button
                  key={sp.id}
                  onClick={() => handleSpeedChange(sp.id)}
                  className={`px-2 py-0.5 rounded text-[11px] transition ${
                    demoSpeed === sp.id || (sp.id === 'normal' && demoSpeed === 'standard')
                      ? 'bg-slate-700 text-white font-bold border border-slate-600'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {sp.label}
                </button>
              ))}
            </div>

            {/* Reset Button */}
            <button
              onClick={handleResetDemoSession}
              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-white rounded text-xs font-semibold flex items-center gap-1 transition"
              title="Reset isolated demo session"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Reset Demo</span>
            </button>
          </div>
        </div>

        {/* 5 Compact Scenario Selection Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
          {Object.values(SCENARIOS).map((sc) => {
            const isSelected = selectedScenarioKey === sc.id;
            return (
              <button
                key={sc.id}
                onClick={() => {
                  if (demoTimerRef.current) {
                    clearTimeout(demoTimerRef.current);
                    demoTimerRef.current = null;
                  }
                  setDemoRunning(false);
                  demoRunningRef.current = false;
                  setDemoPaused(false);
                  demoPausedRef.current = false;
                  setSelectedScenarioKey(sc.id);
                  setDemoCurrentStepIndex(0);
                  setDemoEventsLog([]);
                  setDemoTransitionAlert(null);
                  setDemoSessionState(null);
                  setDemoLastResponse(null);
                  setDemoStepError(null);
                }}
                className={`p-2.5 rounded text-left border transition text-xs flex flex-col justify-between ${
                  isSelected
                    ? 'bg-slate-800 border-slate-600 text-white font-semibold'
                    : 'bg-slate-950/70 border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                }`}
              >
                <div className="flex items-center gap-1.5 font-bold truncate">
                  <Target className={`w-3.5 h-3.5 ${isSelected ? 'text-cyan-400' : 'text-slate-500'}`} />
                  <span className="truncate">{sc.title}</span>
                </div>
                <div className="text-[10px] text-slate-500 mt-1 font-mono">
                  {sc.steps.length} sequential steps
                </div>
              </button>
            );
          })}
        </div>

        {/* Simulator Progression & Execution Bar */}
        <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-3">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-2.5">
            <div className="space-y-0.5">
              <div className="text-xs font-bold text-white flex items-center gap-2 flex-wrap">
                <span>Target:</span>
                <span className="text-cyan-400 font-mono">{currentScenario.sessionId}</span>
                <span className="text-slate-500 font-mono">({currentScenario.ip})</span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
                  Step {demoCurrentStepIndex} of {currentScenario.steps.length}
                </span>
                {demoCurrentStepIndex >= currentScenario.steps.length && (
                  <span className="text-emerald-400 font-semibold text-[11px] flex items-center gap-1 bg-emerald-950/60 px-1.5 py-0.2 rounded border border-emerald-800">
                    <CheckCircle2 className="w-3 h-3 text-emerald-400 inline" />
                    Complete
                  </span>
                )}
              </div>
            </div>

            {/* Run / Controls Buttons */}
            <div className="flex items-center gap-1.5 flex-wrap">
              {(!demoRunning || demoCurrentStepIndex >= currentScenario.steps.length) && (
                <button
                  onClick={handleRunScenario}
                  disabled={demoExecuting}
                  className="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-white font-bold rounded text-xs flex items-center gap-1 transition disabled:opacity-50"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>{demoCurrentStepIndex >= currentScenario.steps.length ? 'Re-run' : 'Run Scenario'}</span>
                </button>
              )}

              {demoRunning && !demoPaused && demoSpeed !== 'step' && (
                <button
                  onClick={handlePause}
                  className="px-3 py-1 bg-amber-600 hover:bg-amber-500 text-white font-bold rounded text-xs flex items-center gap-1 transition"
                >
                  <Pause className="w-3.5 h-3.5" />
                  <span>Pause</span>
                </button>
              )}

              {demoPaused && demoSpeed !== 'step' && (
                <button
                  onClick={handleResume}
                  className="px-3 py-1 bg-slate-700 hover:bg-slate-600 text-white font-bold rounded text-xs flex items-center gap-1 transition"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Resume</span>
                </button>
              )}

              {demoSpeed === 'step' && demoCurrentStepIndex < currentScenario.steps.length && (
                <button
                  onClick={handleManualNextStep}
                  disabled={demoExecuting}
                  className="px-3 py-1 bg-slate-700 hover:bg-slate-600 text-white font-bold rounded text-xs flex items-center gap-1 transition disabled:opacity-50"
                >
                  <ChevronRight className="w-3.5 h-3.5" />
                  <span>Execute Next Step</span>
                </button>
              )}

              {demoRunning && (
                <button
                  onClick={handleStop}
                  className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs font-medium transition"
                >
                  <Square className="w-3 h-3 text-slate-400" />
                  <span>Stop</span>
                </button>
              )}

              <button
                onClick={handleRestartScenario}
                className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs font-medium transition"
                title="Restart from Step 1"
              >
                <RotateCcw className="w-3 h-3 text-slate-400" />
                <span>Restart</span>
              </button>
            </div>
          </div>

          {/* Compact Progress Bar */}
          <div className="w-full bg-slate-900 border border-slate-800 rounded-full h-1.5 overflow-hidden">
            <div
              className={`h-full transition-all duration-300 ${
                demoCurrentStepIndex >= currentScenario.steps.length ? 'bg-emerald-500' : 'bg-slate-500'
              }`}
              style={{
                width: `${Math.min(100, Math.round((demoCurrentStepIndex / currentScenario.steps.length) * 100))}%`,
              }}
            />
          </div>

          {/* Error Banner if any */}
          {demoStepError && (
            <div className="p-2 bg-rose-950/60 border border-rose-800 rounded text-rose-200 text-xs flex items-center justify-between">
              <span>{demoStepError}</span>
              <button
                onClick={handleRunScenario}
                className="px-2 py-0.5 bg-rose-900 hover:bg-rose-800 text-white rounded text-[11px]"
              >
                Retry
              </button>
            </div>
          )}

          {/* 5 Real-Time Threat Progression Blocks */}
          <div className="pt-2 border-t border-slate-800/80">
            <div className="grid grid-cols-5 gap-1.5 text-center text-[10px] font-mono font-semibold">
              <div
                className={`p-2 rounded border transition ${
                  (demoSessionState?.risk_score || 0) < 30
                    ? 'bg-emerald-950/60 border-emerald-600 text-emerald-300'
                    : 'bg-slate-900 border-slate-800 text-slate-500'
                }`}
              >
                <div>0–29: NORMAL</div>
                <div className="text-[9px] font-normal text-slate-400">Route: Real</div>
              </div>

              <div
                className={`p-2 rounded border transition ${
                  (demoSessionState?.risk_score || 0) >= 30 && (demoSessionState?.risk_score || 0) < 50
                    ? 'bg-amber-950/60 border-amber-600 text-amber-300'
                    : 'bg-slate-900 border-slate-800 text-slate-500'
                }`}
              >
                <div>30–49: SUSPICIOUS</div>
                <div className="text-[9px] font-normal text-slate-400">Monitoring</div>
              </div>

              <div
                className={`p-2 rounded border transition ${
                  (demoSessionState?.risk_score || 0) >= 50 && (demoSessionState?.risk_score || 0) < 70
                    ? 'bg-orange-950/60 border-orange-600 text-orange-300'
                    : 'bg-slate-900 border-slate-800 text-slate-500'
                }`}
              >
                <div>50–69: HIGH RISK</div>
                <div className="text-[9px] font-normal text-slate-400">Scrutiny</div>
              </div>

              <div
                className={`p-2 rounded border transition ${
                  (demoSessionState?.risk_score || 0) >= 70 && !demoSessionState?.is_diverted
                    ? 'bg-rose-950/60 border-rose-600 text-rose-300'
                    : 'bg-slate-900 border-slate-800 text-slate-500'
                }`}
              >
                <div>70+: LIKELY MALICIOUS</div>
                <div className="text-[9px] font-normal text-slate-400">&ge;2 Categories</div>
              </div>

              <div
                className={`p-2 rounded border transition ${
                  demoSessionState?.is_diverted
                    ? 'bg-rose-950/80 border-rose-500 text-rose-200'
                    : 'bg-slate-900 border-slate-800 text-slate-500'
                }`}
              >
                <div>REAL-TO-DECOY</div>
                <div className="text-[9px] font-normal text-rose-400">Trapped in Decoy</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ================================================================== */}
      {/* 6. DECOY LATENCY & ATTACKER OBSERVATION (2-COLUMN LAYOUT)          */}
      {/* ================================================================== */}
      <div className="rounded-lg bg-slate-900/60 border border-slate-800 p-4 font-mono space-y-3.5 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-2.5">
          <div className="flex items-center space-x-2">
            <Hourglass className="w-4 h-4 text-slate-400" />
            <h2 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
              Decoy Latency & Attacker Observation
            </h2>
          </div>

          <div className="flex items-center space-x-2">
            <span
              className={`text-xs px-2 py-0.5 rounded font-semibold border flex items-center gap-1.5 ${
                decoyLatencyMode === 'controlled'
                  ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800'
                  : 'bg-slate-800 text-slate-300 border-slate-700'
              }`}
            >
              <Clock className="w-3 h-3" />
              <span>{decoyLatencyMode === 'controlled' ? 'CONTROLLED (ACTIVE)' : 'NORMAL (BASELINE)'}</span>
            </span>

            <button
              onClick={handleToggleDecoyLatencyMode}
              className="px-2.5 py-0.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-white rounded text-xs font-medium transition"
            >
              Toggle Mode
            </button>
          </div>
        </div>

        {/* 2-Column Content Layout */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* LEFT: 4 KPI Cards, Profiles & Comparison Simulator */}
          <div className="space-y-3">
            {/* 4 Compact Latency & Engagement Stats */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              <div className="p-2.5 bg-slate-950 border border-slate-800 rounded">
                <div className="text-[10px] text-slate-500 uppercase">Avg Decoy Latency</div>
                <div className="text-base font-bold text-slate-100 mt-0.5">
                  {decoyStats?.average_response_latency_ms
                    ? `${decoyStats.average_response_latency_ms.toFixed(0)} ms`
                    : decoyLatencyMode === 'controlled'
                    ? '2,480 ms'
                    : '14 ms'}
                </div>
              </div>

              <div className="p-2.5 bg-slate-950 border border-slate-800 rounded">
                <div className="text-[10px] text-slate-500 uppercase">Avg Engagement</div>
                <div className="text-base font-bold text-slate-100 mt-0.5">
                  {decoyStats?.average_session_duration_seconds
                    ? `${(decoyStats.average_session_duration_seconds / 60).toFixed(1)} min`
                    : '3.6 min'}
                </div>
              </div>

              <div className="p-2.5 bg-slate-950 border border-slate-800 rounded">
                <div className="text-[10px] text-slate-500 uppercase">Probes Trapped</div>
                <div className="text-base font-bold text-slate-100 mt-0.5">
                  {decoyStats?.total_attacker_requests || 0}
                </div>
              </div>

              <div className="p-2.5 bg-slate-950 border border-slate-800 rounded">
                <div className="text-[10px] text-slate-500 uppercase">Canary Hits</div>
                <div className="text-base font-bold text-amber-300 mt-0.5">
                  {decoyStats?.honeytoken_hits || 0}
                </div>
              </div>
            </div>

            {/* Configured Profiles & Comparison Tool in sub-panels */}
            <div className="p-3 bg-slate-950 border border-slate-800 rounded space-y-2.5">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-1.5">
                <span className="text-[11px] font-bold text-slate-300 uppercase">Configured Latency Profiles</span>
                <span className="text-[10px] text-slate-500">FastAPI Async Traps</span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5 text-[11px]">
                {[
                  { name: 'Fake Login', path: '/auth/login', delay: '1–2s' },
                  { name: 'Fake OTP', path: '/auth/otp', delay: '2–3s' },
                  { name: 'Fake Admin', path: '/admin', delay: '2–4s' },
                  { name: 'Database API', path: '/api/db', delay: '2–5s' },
                  { name: 'Payment API', path: '/charge', delay: '3–5s' },
                  { name: 'Honeytoken', path: '/.env', delay: '1–3s' },
                ].map((p, pIdx) => (
                  <div key={pIdx} className="p-1.5 rounded bg-slate-900 border border-slate-800 flex justify-between items-center">
                    <span className="text-slate-300 text-[10px] truncate">{p.name}</span>
                    <span className="text-cyan-400 font-bold text-[10px] shrink-0">{p.delay}</span>
                  </div>
                ))}
              </div>

              {/* Latency Comparison Tool */}
              <div className="pt-2 border-t border-slate-800/80 space-y-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <select
                    value={comparisonCategory}
                    onChange={(e) => setComparisonCategory(e.target.value)}
                    className="bg-slate-900 border border-slate-800 rounded px-2 py-1 text-xs text-white outline-none"
                  >
                    <option value="auth_login">Login (Profile: 1–2s)</option>
                    <option value="auth_otp">OTP Challenge (Profile: 2–3s)</option>
                    <option value="admin_console">Admin Console (Profile: 2–4s)</option>
                    <option value="database_api">DB API (Profile: 2–5s)</option>
                    <option value="payment_gateway">Payment (Profile: 3–5s)</option>
                    <option value="honeytoken">Honeytoken (Profile: 1–3s)</option>
                  </select>

                  <button
                    onClick={handleRunComparisonDemo}
                    disabled={runningComparison}
                    className="px-3 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-semibold rounded transition disabled:opacity-50"
                  >
                    {runningComparison ? 'Measuring...' : 'Compare Normal vs Controlled'}
                  </button>
                </div>

                {comparisonResult && (
                  <div className="p-2 rounded bg-slate-900 border border-slate-800 text-[11px] space-y-1">
                    <div className="flex justify-between text-slate-400">
                      <span>Normal: <strong className="text-slate-200">{comparisonResult.normal_mode.measured_response_ms.toFixed(0)}ms</strong></span>
                      <span>Controlled: <strong className="text-cyan-400">{comparisonResult.controlled_mode.measured_response_ms.toFixed(0)}ms</strong></span>
                      <span className="text-emerald-400 font-bold">Dilation: {comparisonResult.observation_benefit.time_dilation_factor}x</span>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* RIGHT: Live Attacker Observation Stream */}
          <div className="p-3 bg-slate-950 border border-slate-800 rounded flex flex-col justify-between space-y-2">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <span className="text-xs font-semibold text-slate-200 uppercase flex items-center gap-1.5">
                <Radio className="w-3.5 h-3.5 text-cyan-400" />
                Live Attacker Observation Stream
              </span>
              <span className="text-[10px] text-slate-500">Decoy Honeynet Telemetry</span>
            </div>

            <div className="space-y-1.5 overflow-y-auto max-h-[290px] pr-1">
              {!decoyStats?.recent_interactions || decoyStats.recent_interactions.length === 0 ? (
                <div className="py-12 text-center text-slate-500 text-xs italic">
                  Zero active decoy interactions logged. Trigger an attack scenario above to stream telemetry.
                </div>
              ) : (
                decoyStats.recent_interactions.map((item, idx) => (
                  <div
                    key={idx}
                    className="p-2 rounded bg-slate-900 border border-slate-800/80 hover:border-slate-700 text-xs space-y-1 transition"
                  >
                    <div className="flex items-center justify-between text-[11px]">
                      <div className="flex items-center space-x-1.5 truncate">
                        <span className="font-bold text-slate-200 truncate">{item.method || 'GET'} {item.endpoint}</span>
                        {item.is_honeytoken && (
                          <span className="text-[9px] px-1 py-0.2 rounded bg-purple-950 text-purple-300 border border-purple-800 font-semibold">
                            HONEYTOKEN
                          </span>
                        )}
                      </div>
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-cyan-300 font-semibold shrink-0">
                        +{item.delay_applied_seconds ? `${item.delay_applied_seconds.toFixed(2)}s delay` : `${item.latency_ms?.toFixed(0) || 0}ms`}
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-[10px] text-slate-500">
                      <span>IP: {item.src_ip || '198.51.100.99'}</span>
                      <span>{item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : 'Recent'}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ================================================================== */}
      {/* 7. VISITOR SESSIONS & RISK PROFILES (ENTERPRISE DATA TABLE)       */}
      {/* ================================================================== */}
      <div className="rounded-lg bg-slate-900/60 border border-slate-800 p-4 font-mono space-y-3 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-2.5">
          <div>
            <h2 className="text-xs font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <UserCheck className="w-4 h-4 text-slate-400" />
              Visitor Sessions & Behaviour Risk Profiles
            </h2>
          </div>
          <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 self-start sm:self-auto">
            {filteredSessions.length} Tracked Sessions
          </span>
        </div>

        {/* Filter & Search Bar */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 text-xs">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search IP, Session, or Account..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-3 py-1 bg-slate-950 border border-slate-800 rounded text-xs text-white placeholder-slate-500 focus:border-slate-600 outline-none"
            />
          </div>

          <div className="flex items-center gap-1 overflow-x-auto text-xs">
            <span className="text-slate-500 text-[11px]">Class:</span>
            {['ALL', 'NORMAL', 'SUSPICIOUS', 'HIGH_RISK', 'LIKELY_MALICIOUS'].map((c) => (
              <button
                key={c}
                onClick={() => setClassificationFilter(c)}
                className={`px-2 py-0.5 rounded text-[10px] font-semibold transition border ${
                  classificationFilter === c
                    ? 'bg-slate-700 text-white border-slate-600'
                    : 'bg-slate-950 text-slate-400 border-slate-800 hover:border-slate-700'
                }`}
              >
                {c === 'LIKELY_MALICIOUS' ? 'MALICIOUS' : c}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1 justify-end text-xs">
            <span className="text-slate-500 text-[11px]">Route:</span>
            {['ALL', 'REAL', 'DECOY'].map((r) => (
              <button
                key={r}
                onClick={() => setRouteFilter(r)}
                className={`px-2.5 py-0.5 rounded text-[10px] font-semibold transition border ${
                  routeFilter === r
                    ? 'bg-slate-700 text-white border-slate-600'
                    : 'bg-slate-950 text-slate-400 border-slate-800 hover:border-slate-700'
                }`}
              >
                {r}
              </button>
            ))}
          </div>
        </div>

        {/* Sessions Data Table */}
        <div className="overflow-x-auto border border-slate-800 rounded-lg">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 text-[11px]">
              <tr>
                <th className="py-2 px-3">Session ID</th>
                <th className="py-2 px-3">Visitor IP</th>
                <th className="py-2 px-3">Account</th>
                <th className="py-2 px-3 text-center">Score (0–100)</th>
                <th className="py-2 px-3">Classification</th>
                <th className="py-2 px-3">Categories</th>
                <th className="py-2 px-3">Route</th>
                <th className="py-2 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
              {filteredSessions.length === 0 ? (
                <tr>
                  <td colSpan={8} className="text-center py-8 text-slate-500">
                    No visitor sessions match the current filter.
                  </td>
                </tr>
              ) : (
                filteredSessions.map((sess) => {
                  const score = Number(sess.risk_score || 0);
                  const isDiverted = sess.is_diverted || sess.current_route === 'decoy';
                  return (
                    <tr
                      key={sess.session_id}
                      className="hover:bg-slate-800/30 transition cursor-pointer"
                      onClick={() => handleInspectSession(sess)}
                    >
                      <td className="py-2 px-3 text-slate-300 font-bold" title={sess.session_id}>
                        {sess.session_id.slice(0, 14)}...
                      </td>
                      <td className="py-2 px-3 text-slate-200">{sess.src_ip}</td>
                      <td className="py-2 px-3 text-slate-400 truncate max-w-[120px]">
                        {sess.account_email || <span className="text-slate-600 italic">anonymous</span>}
                      </td>
                      <td className="py-2 px-3">
                        <div className="flex items-center space-x-2 justify-center">
                          <span className={`font-bold ${getScoreColor(score)}`}>
                            {score.toFixed(1)}
                          </span>
                          <div className="w-12 bg-slate-950 rounded-full h-1.5 overflow-hidden border border-slate-800">
                            <div
                              className={`h-full ${getScoreBarBg(score)}`}
                              style={{ width: `${Math.min(100, Math.max(0, score))}%` }}
                            />
                          </div>
                        </div>
                      </td>
                      <td className="py-2 px-3">
                        <span
                          className={`px-1.5 py-0.2 rounded text-[10px] font-semibold uppercase border ${getClassificationBadge(
                            sess.risk_classification
                          )}`}
                        >
                          {sess.risk_classification || 'NORMAL'}
                        </span>
                      </td>
                      <td className="py-2 px-3">
                        <span className="px-1.5 py-0.2 bg-slate-900 border border-slate-800 rounded text-slate-300 text-[10px]">
                          {sess.independent_categories_count || (sess.active_categories ? Object.keys(sess.active_categories).length : 0)} active
                        </span>
                      </td>
                      <td className="py-2 px-3">
                        {isDiverted ? (
                          <span className="px-1.5 py-0.2 bg-rose-950/60 border border-rose-800 text-rose-300 rounded text-[10px] font-semibold flex items-center gap-1 w-fit">
                            <ShieldAlert className="w-3 h-3 text-rose-400" />
                            DECOY
                          </span>
                        ) : (
                          <span className="px-1.5 py-0.2 bg-emerald-950/60 border border-emerald-800 text-emerald-300 rounded text-[10px] font-semibold flex items-center gap-1 w-fit">
                            <CheckCircle className="w-3 h-3 text-emerald-400" />
                            REAL
                          </span>
                        )}
                      </td>
                      <td className="py-2 px-3 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleInspectSession(sess);
                          }}
                          className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded text-slate-300 hover:text-white text-[10px] flex items-center gap-1 ml-auto"
                        >
                          <Eye className="w-3 h-3" />
                          <span>Inspect</span>
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Session Detailed Inspection Modal */}
      {selectedSession && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 font-mono">
          <div className="bg-slate-900 border border-slate-800 rounded-lg max-w-2xl w-full p-5 space-y-4 shadow-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <UserCheck className="w-4 h-4 text-cyan-400" />
                  Session Profile: {selectedSession.session_id}
                </h3>
                <div className="text-[11px] text-slate-400 mt-0.5">
                  IP: {selectedSession.src_ip} &bull; Route: <strong className={selectedSession.is_diverted ? 'text-rose-400' : 'text-emerald-400'}>{selectedSession.is_diverted ? 'DECOY' : 'REAL'}</strong>
                </div>
              </div>
              <button
                onClick={() => setSelectedSession(null)}
                className="text-slate-400 hover:text-white p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {loadingDetail ? (
              <div className="py-8 text-center text-xs text-slate-400">Loading full session profile breakdown...</div>
            ) : sessionDetail ? (
              <div className="space-y-3 text-xs">
                <div className="flex items-center justify-between p-3 rounded bg-slate-950 border border-slate-800">
                  <div>
                    <div className="text-[10px] text-slate-500 uppercase">Cumulative Threat Score</div>
                    <div className="text-xl font-bold text-slate-100">{sessionDetail.risk_score?.toFixed(1)} / 100.0</div>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[11px] font-bold border ${getClassificationBadge(sessionDetail.risk_classification)}`}>
                    {sessionDetail.risk_classification}
                  </span>
                </div>

                <div className="space-y-1.5">
                  <span className="text-[11px] text-slate-400 font-bold uppercase">Category Points Breakdown:</span>
                  <div className="grid grid-cols-2 gap-2 text-[11px]">
                    {Object.entries(sessionDetail.categories || {}).map(([catKey, catVal]) => (
                      <div key={catKey} className="p-2 rounded bg-slate-950 border border-slate-800 flex justify-between items-center">
                        <span className="text-slate-300 truncate pr-2">{catKey.replace(/_/g, ' ')}</span>
                        <span className="font-bold text-cyan-400 shrink-0">{Number(catVal?.points || catVal || 0).toFixed(1)} pts</span>
                      </div>
                    ))}
                  </div>
                </div>

                {sessionDetail.reasons && sessionDetail.reasons.length > 0 && (
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800 space-y-1">
                    <span className="text-[10px] uppercase font-bold text-slate-500">Trigger Reasons:</span>
                    <ul className="list-disc pl-4 text-[11px] text-slate-300 space-y-0.5">
                      {sessionDetail.reasons.map((r, rIdx) => (
                        <li key={rIdx}>{r}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ) : (
              <div className="py-4 text-center text-xs text-slate-500">No telemetry recorded for session.</div>
            )}

            <div className="pt-2 border-t border-slate-800 text-right">
              <button
                onClick={() => setSelectedSession(null)}
                className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ================================================================== */}
      {/* 8. DYNAMIC ROUTING & RECENT DECISIONS (2-COLUMN LAYOUT)            */}
      {/* ================================================================== */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 font-mono text-xs">
        {/* Left: Dynamic Routing Decision Simulator */}
        <div className="rounded-lg bg-slate-900/60 border border-slate-800 p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
            <h2 className="text-xs font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
              <Zap className="w-3.5 h-3.5 text-cyan-400" />
              Dynamic Routing Decision Simulator
            </h2>
            <span className="text-[10px] text-slate-500">Live Policy Test</span>
          </div>

          <div className="space-y-2.5">
            <div>
              <label className="text-slate-400 block mb-1 text-[11px]">Visitor / Attacker IP:</label>
              <input
                type="text"
                value={simIp}
                onChange={(e) => setSimIp(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded p-1.5 text-white font-mono text-xs focus:border-slate-600 outline-none"
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-slate-400 block mb-1 text-[11px]">Target Path:</label>
                <input
                  type="text"
                  value={simPath}
                  onChange={(e) => setSimPath(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-1.5 text-white font-mono text-xs focus:border-slate-600 outline-none"
                />
              </div>
              <div>
                <label className="text-slate-400 block mb-1 text-[11px]">HTTP Method:</label>
                <select
                  value={simMethod}
                  onChange={(e) => setSimMethod(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-1.5 text-white font-mono text-xs focus:border-slate-600 outline-none"
                >
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                  <option value="DELETE">DELETE</option>
                </select>
              </div>
            </div>

            <div className="flex gap-2 pt-1">
              <button
                onClick={handleSimulate}
                disabled={simulating}
                className="flex-1 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-white font-bold rounded transition flex items-center justify-center space-x-1.5 disabled:opacity-50"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>{simulating ? 'Evaluating...' : 'Dispatch Request & Evaluate Route'}</span>
              </button>
              <button
                onClick={handleResetVisitor}
                title="Reset this IP's risk score"
                className="px-2.5 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 rounded border border-slate-800 flex items-center justify-center space-x-1 transition"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Reset IP</span>
              </button>
            </div>
          </div>

          {/* Simulator Result Box */}
          {simResult && (
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800 space-y-1.5 text-xs">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Decision Route:</span>
                <span
                  className={`px-2 py-0.5 rounded font-bold uppercase ${
                    simResult.routed_to === 'decoy'
                      ? 'bg-rose-950 text-rose-300 border border-rose-800'
                      : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  }`}
                >
                  {simResult.routed_to} (Risk: {simResult.risk_score.toFixed(1)}/100)
                </span>
              </div>
              <div className="text-[11px] text-slate-300 truncate">
                Destination: <span className="text-cyan-300">{simResult.dispatched_url}</span>
              </div>
              <div className="text-[11px] text-slate-400 italic bg-slate-900/60 p-1.5 rounded">
                &ldquo;{simResult.decision_reason}&rdquo;
              </div>
            </div>
          )}

          {/* Compact Policy Thresholds Legend */}
          <div className="pt-2 border-t border-slate-800 text-[11px] text-slate-500 space-y-0.5">
            <div>&bull; <strong className="text-emerald-400">0–69 pts:</strong> Routed to Real Application workload.</div>
            <div>&bull; <strong className="text-rose-400">70–100 pts:</strong> Diverted to isolated Decoy (requires &ge; 2 categories).</div>
          </div>
        </div>

        {/* Right: Recent Gateway Decisions Stream */}
        <div className="rounded-lg bg-slate-900/60 border border-slate-800 p-4 space-y-3 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
              <h2 className="text-xs font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-slate-400" />
                Recent Gateway Routing Decisions
              </h2>
              <span className="text-[10px] text-slate-500">Live Feed</span>
            </div>

            <div className="space-y-2 overflow-y-auto max-h-[360px] pr-1">
              {(!stats?.recent_decisions || stats.recent_decisions.length === 0) ? (
                <div className="py-12 text-center text-xs text-slate-500">
                  No gateway requests recorded yet. Dispatch a test request on the left.
                </div>
              ) : (
                stats.recent_decisions.map((log) => (
                  <div
                    key={log.id}
                    className="p-2.5 bg-slate-950/70 border border-slate-800/80 rounded text-xs hover:border-slate-700 transition space-y-1"
                  >
                    <div className="flex items-center justify-between text-[11px]">
                      <div className="flex items-center space-x-1.5 min-w-0">
                        <span className="font-bold text-slate-200">{log.src_ip}</span>
                        <span className="text-slate-500">&bull;</span>
                        <span className="text-slate-400 truncate">{log.method} {log.path}</span>
                      </div>
                      <span
                        className={`px-1.5 py-0.2 rounded text-[10px] font-bold uppercase shrink-0 ${
                          log.routed_to === 'decoy'
                            ? 'bg-rose-950 text-rose-300 border border-rose-800'
                            : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                        }`}
                      >
                        {log.routed_to} ({log.risk_score?.toFixed(0) || 0})
                      </span>
                    </div>

                    <div className="text-[11px] text-slate-400 bg-slate-900/60 p-1.5 rounded truncate">
                      {log.decision_reason}
                    </div>

                    <div className="flex items-center justify-between text-[10px] text-slate-500 pt-0.5">
                      <span>Latency: {log.response_time_ms}ms</span>
                      <span>{log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : 'Recent'}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
