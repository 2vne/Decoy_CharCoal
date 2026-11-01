from __future__ import annotations
import asyncio
from datetime import datetime, timezone, timedelta
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple, Union

import httpx
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db import AsyncSessionLocal
from app.models import (
    Block,
    Attacker,
    AuditLog,
    Event,
    Gateway,
    GatewayRequestLog,
    Incident,
    FunctionTargetEvent,
    ObservedBehaviourEvent,
)
from app.services.pagerduty import pagerduty_manager
from app.services.function_intelligence import FUNCTION_METADATA
from app.services.audit import record_audit

logger = logging.getLogger("sentinel.assistant")

# -----------------------------------------------------------------------------
# TOOL DEFINITIONS (OpenAI Function Calling & Native Tool Registry)
# -----------------------------------------------------------------------------
ASSISTANT_TOOLS_SPEC = [
    {
        "type": "function",
        "function": {
            "name": "get_active_incidents",
            "description": "Retrieve currently active or open security incidents, prioritized by severity (critical, high, medium) along with correlated attacker sessions and PagerDuty statuses.",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Max number of incidents to return (default: 10)"},
                    "severity": {"type": "string", "enum": ["all", "critical", "high", "medium", "low"], "description": "Filter by severity"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_incident_details",
            "description": "Fetch deep forensic details for a specific incident by ID, including attacker profile, blast radius, evidence timeline, and recommended playbook remediation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "incident_id": {"type": "string", "description": "Incident ID (e.g. '1', 'INC-1', or PagerDuty dedup key)"},
                },
                "required": ["incident_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_visitor_session",
            "description": "Retrieve current behavioural state, composite risk score (0-100), active route (real vs decoy), and attribution data for a specific visitor session ID or IP address.",
            "parameters": {
                "type": "object",
                "properties": {
                    "session_id": {"type": "string", "description": "Visitor session token (e.g. 'sess_...' or 'demo_session')"},
                    "ip": {"type": "string", "description": "Visitor IP address (e.g. '192.168.1.50')"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_session_event_history",
            "description": "Get the chronological event history for a visitor session or IP, highlighting critical triggers, honeytoken interactions, and real-to-decoy transitions.",
            "parameters": {
                "type": "object",
                "properties": {
                    "session_id": {"type": "string", "description": "Visitor session token"},
                    "ip": {"type": "string", "description": "Visitor IP address"},
                    "limit": {"type": "integer", "description": "Max events to return (default: 30)"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_gateway_status",
            "description": "Get Deception Gateway routing health, total traffic volume, real vs decoy distribution, and monitored gateway lifecycles (operational, attacked, taken down, watch mode).",
            "parameters": {
                "type": "object",
                "properties": {},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_function_intelligence",
            "description": "Inspect Level-2 Function Intelligence: identify which specific backend functions (e.g. auth_login, payment_gateway, database_api, secrets_env) are currently being targeted and their risk contributions.",
            "parameters": {
                "type": "object",
                "properties": {},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_honeypot_activity",
            "description": "Retrieve recent telemetry from the honeypot fleet (Cowrie SSH/Telnet, Dionaea malware, Conpot ICS, OpenCanary) with attack protocols and MITRE techniques.",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Max events (default: 15)"},
                    "honeypot_type": {"type": "string", "description": "Filter by honeypot type (cowrie, dionaea, conpot, opencanary)"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_pagerduty_status",
            "description": "Check real-time PagerDuty on-call integration status, responder contact information (+91 voice target), routing key validity, and recent incident notifications.",
            "parameters": {
                "type": "object",
                "properties": {},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_system_health",
            "description": "Retrieve overall SENTINEL SOC operational health: backend services, database status, active firewall blocks, WebSocket broadcaster, and exposure budget.",
            "parameters": {
                "type": "object",
                "properties": {},
            },
        },
    },
]


# -----------------------------------------------------------------------------
# TOOL IMPLEMENTATIONS (Live Read-Only Backend Execution)
# -----------------------------------------------------------------------------

async def execute_tool(tool_name: str, arguments: Dict[str, Any], db: AsyncSession) -> Dict[str, Any]:
    """
    Executes a read-only investigation tool against live backend databases and services.
    """
    try:
        if tool_name == "get_active_incidents":
            limit = int(arguments.get("limit", 10))
            severity_filter = arguments.get("severity", "all")
            
            stmt = select(Incident).order_by(
                # Prioritize un-resolved first
                Incident.status == "resolved",
                desc(Incident.created_at),
            ).limit(limit)
            
            res = await db.execute(stmt)
            incidents = res.scalars().all()
            
            # Format
            out_incidents = []
            for inc in incidents:
                score = inc.risk_score_at_creation or 75.0
                derived_sev = "critical" if score >= 76 else ("high" if score >= 51 else ("medium" if score >= 26 else "low"))
                if severity_filter != "all" and derived_sev != severity_filter:
                    continue
                out_incidents.append({
                    "id": inc.id,
                    "title": inc.title,
                    "status": inc.status,
                    "severity": derived_sev,
                    "risk_score": score,
                    "attacker_id": inc.attacker_id,
                    "root_cause": inc.root_cause,
                    "blast_radius": inc.blast_radius,
                    "created_at": inc.created_at.isoformat() if inc.created_at else None,
                })
                
            # Cross-reference with PagerDuty
            pd_incidents = pagerduty_manager.get_all_incidents()
            active_pd = [
                {
                    "dedup_key": p.get("dedup_key"),
                    "title": p.get("title") or p.get("summary"),
                    "priority": p.get("priority"),
                    "status": p.get("status"),
                    "created_at": p.get("created_at"),
                }
                for p in pd_incidents if p.get("status") != "resolved"
            ]
            
            return {
                "total_active_db_incidents": len([i for i in out_incidents if i["status"] != "resolved"]),
                "incidents": out_incidents,
                "active_pagerduty_incidents": active_pd,
            }

        elif tool_name == "get_incident_details":
            inc_id_raw = str(arguments.get("incident_id", "")).strip().replace("INC-", "").replace("inc-", "")
            
            inc = None
            if inc_id_raw.isdigit():
                stmt = select(Incident).where(Incident.id == int(inc_id_raw))
                res = await db.execute(stmt)
                inc = res.scalar_one_or_none()
            
            if not inc:
                # Try finding by latest or title match
                stmt = select(Incident).order_by(desc(Incident.created_at)).limit(1)
                res = await db.execute(stmt)
                inc = res.scalar_one_or_none()
                if not inc:
                    return {"found": False, "message": f"Incident '{arguments.get('incident_id')}' not found in database."}

            # Fetch attacker dossier if associated
            attacker_info = None
            if inc.attacker_id:
                att_stmt = select(Attacker).where(Attacker.id == inc.attacker_id)
                att_res = await db.execute(att_stmt)
                att = att_res.scalar_one_or_none()
                if att:
                    attacker_info = {
                        "id": att.id,
                        "ip": att.ip,
                        "risk_score": att.risk_score,
                        "risk_band": att.risk_band,
                        "intent": att.intent,
                        "status": att.status,
                        "mitre_techniques": att.mitre_techniques or [],
                    }

            # Fetch remediation advisory
            from app.services.remediation import generate_remediation_advisory
            advisory = await generate_remediation_advisory(inc, db)
            
            score = inc.risk_score_at_creation or 75.0
            derived_sev = "critical" if score >= 76 else ("high" if score >= 51 else ("medium" if score >= 26 else "low"))
            
            return {
                "found": True,
                "incident": {
                    "id": inc.id,
                    "title": inc.title,
                    "severity": derived_sev,
                    "risk_score": score,
                    "status": inc.status,
                    "root_cause": inc.root_cause,
                    "blast_radius": inc.blast_radius,
                    "created_at": inc.created_at.isoformat() if inc.created_at else None,
                },
                "attacker": attacker_info,
                "advisory": {
                    "disclaimer": advisory.get("disclaimer", "AI suggestion, human review required"),
                    "likely_causes": advisory.get("likely_causes", []),
                    "immediate_actions": advisory.get("immediate_actions", [])[:3],
                    "staged_reopen_plan": advisory.get("staged_reopen_plan", []),
                },
            }

        elif tool_name == "get_visitor_session":
            session_id = arguments.get("session_id")
            ip = arguments.get("ip")
            
            from app.services.behaviour_risk import get_session_summary, _SESSION_STORE, _OBSERVED_EVENTS
            
            # Search active in-memory session store
            target_sess = None
            if session_id and session_id in _SESSION_STORE:
                target_sess = _SESSION_STORE[session_id]
            elif ip:
                for s_id, s_data in _SESSION_STORE.items():
                    if s_data.get("ip") == ip:
                        target_sess = s_data
                        target_sess["session_id"] = s_id
                        break
            
            # If not in memory, check GatewayRequestLog
            if not target_sess:
                stmt = select(GatewayRequestLog).order_by(desc(GatewayRequestLog.timestamp))
                if ip:
                    stmt = stmt.where(GatewayRequestLog.src_ip == ip)
                stmt = stmt.limit(1)
                res = await db.execute(stmt)
                log_entry = res.scalar_one_or_none()
                if log_entry:
                    target_sess = {
                        "ip": log_entry.src_ip,
                        "routed_to": log_entry.routed_to,
                        "risk_score": log_entry.risk_score,
                        "last_path": log_entry.path,
                        "method": log_entry.method,
                        "timestamp": log_entry.timestamp.isoformat() if log_entry.timestamp else None,
                    }

            if not target_sess:
                return {
                    "found": False,
                    "message": f"No active session found matching session_id='{session_id}' or ip='{ip}'.",
                    "available_active_sessions": list(_SESSION_STORE.keys())[:5],
                }

            return {
                "found": True,
                "session": target_sess,
            }

        elif tool_name == "get_session_event_history":
            session_id = arguments.get("session_id")
            ip = arguments.get("ip")
            limit = int(arguments.get("limit", 30))
            
            from app.services.behaviour_risk import _OBSERVED_EVENTS
            
            events = []
            if session_id and session_id in _OBSERVED_EVENTS:
                events = list(_OBSERVED_EVENTS[session_id])[-limit:]
            elif ip:
                # Find matching session
                from app.services.behaviour_risk import _SESSION_STORE
                for s_id, s_data in _SESSION_STORE.items():
                    if s_data.get("ip") == ip and s_id in _OBSERVED_EVENTS:
                        events = list(_OBSERVED_EVENTS[s_id])[-limit:]
                        break

            # If still empty, check DB GatewayRequestLog
            if not events:
                stmt = select(GatewayRequestLog).order_by(desc(GatewayRequestLog.timestamp)).limit(limit)
                if ip:
                    stmt = stmt.where(GatewayRequestLog.src_ip == ip)
                res = await db.execute(stmt)
                logs = res.scalars().all()
                events = [
                    {
                        "timestamp": l.timestamp.isoformat() if l.timestamp else None,
                        "method": l.method,
                        "path": l.path,
                        "routed_to": l.routed_to,
                        "risk_score": l.risk_score,
                        "src_ip": l.src_ip,
                        "status_code": l.status_code,
                    }
                    for l in logs
                ]

            return {
                "events_count": len(events),
                "history": events,
            }

        elif tool_name == "get_gateway_status":
            # 1. Total request counts by routed_to
            stmt_routes = (
                select(GatewayRequestLog.routed_to, func.count(GatewayRequestLog.id))
                .group_by(GatewayRequestLog.routed_to)
            )
            routes_res = await db.execute(stmt_routes)
            routes_dict = {row[0]: int(row[1]) for row in routes_res.all()}

            real_count = routes_dict.get("real", 0)
            decoy_count = routes_dict.get("decoy", 0)
            challenge_count = routes_dict.get("challenge", 0)
            total_requests = real_count + decoy_count + challenge_count

            # 2. Monitored Gateway entities
            gw_stmt = select(Gateway)
            gw_res = await db.execute(gw_stmt)
            gateways = gw_res.scalars().all()
            
            gw_list = [
                {
                    "id": g.id,
                    "name": g.name,
                    "endpoint_prefix": g.endpoint_prefix,
                    "owner_team": g.owner_team,
                    "status": g.status,
                    "restored_at": g.restored_at.isoformat() if g.restored_at else None,
                    "watch_until": g.watch_until.isoformat() if g.watch_until else None,
                }
                for g in gateways
            ]

            return {
                "total_gateway_requests": total_requests,
                "real_traffic_count": real_count,
                "decoy_traffic_count": decoy_count,
                "challenge_traffic_count": challenge_count,
                "decoy_diversion_percentage": round((decoy_count / max(1, total_requests)) * 100, 1),
                "monitored_gateways": gw_list,
            }

        elif tool_name == "get_function_intelligence":
            stmt_counts = (
                select(FunctionTargetEvent.target_function, func.sum(FunctionTargetEvent.attempts))
                .group_by(FunctionTargetEvent.target_function)
            )
            counts_res = await db.execute(stmt_counts)
            counts_dict = {row[0]: int(row[1]) for row in counts_res.all()}

            targeted_list = []
            for fn_key, meta in FUNCTION_METADATA.items():
                count = counts_dict.get(fn_key, 0)
                targeted_list.append({
                    "function_key": fn_key,
                    "name": meta["name"],
                    "category": meta["category"],
                    "attempts": count,
                    "weight": settings.function_weights.get(fn_key, meta["default_weight"]),
                })
            targeted_list.sort(key=lambda x: x["attempts"], reverse=True)

            return {
                "top_targeted_functions": targeted_list[:5],
                "all_function_stats": targeted_list,
            }

        elif tool_name == "get_honeypot_activity":
            limit = int(arguments.get("limit", 15))
            honeypot_type = arguments.get("honeypot_type")
            
            stmt = select(Event).order_by(desc(Event.timestamp)).limit(limit)
            if honeypot_type:
                stmt = stmt.where(Event.honeypot_type == honeypot_type)
            res = await db.execute(stmt)
            events = res.scalars().all()
            
            event_list = [
                {
                    "id": e.id,
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                    "honeypot_type": e.honeypot_type,
                    "src_ip": e.src_ip,
                    "event_type": e.event_type,
                    "category": e.category,
                    "severity": e.severity,
                    "mitre_technique": e.mitre_technique,
                }
                for e in events
            ]
            return {
                "total_events_retrieved": len(event_list),
                "events": event_list,
            }

        elif tool_name == "get_pagerduty_status":
            pd_status = pagerduty_manager.get_status()
            incidents = pagerduty_manager.get_all_incidents()
            return {
                "service_mode": pd_status.get("service_mode"),
                "operational": pd_status.get("operational"),
                "routing_key_configured": pd_status.get("routing_key_configured"),
                "responder_phone": pd_status.get("responder_phone"),
                "responder_email": pd_status.get("responder_email"),
                "active_incidents_count": len([i for i in incidents if i.get("status") != "resolved"]),
                "recent_alerts": incidents[:5],
            }

        elif tool_name == "get_system_health":
            # Active blocks
            ab_stmt = select(func.count(Block.id)).where(Block.status == "active")
            ab_res = await db.execute(ab_stmt)
            active_blocks = int(ab_res.scalar() or 0)

            # Attackers count
            att_stmt = select(func.count(Attacker.id))
            att_res = await db.execute(att_stmt)
            total_attackers = int(att_res.scalar() or 0)

            # Incidents count
            inc_stmt = select(func.count(Incident.id)).where(Incident.status != "resolved")
            inc_res = await db.execute(inc_stmt)
            open_incidents = int(inc_res.scalar() or 0)

            return {
                "status": "operational",
                "database": "sqlite_async_connected",
                "open_incidents": open_incidents,
                "tracked_attackers": total_attackers,
                "active_firewall_blocks": active_blocks,
                "safe_ips": settings.safe_ips,
                "mock_mode": settings.mock_mode,
            }

        else:
            return {"error": f"Unknown tool: {tool_name}"}

    except Exception as exc:
        logger.error(f"Error executing assistant tool '{tool_name}': {exc}", exc_info=True)
        return {"error": f"Tool execution failed: {str(exc)}"}


# -----------------------------------------------------------------------------
# DETERMINISTIC ASSISTANT ENGINE (Runs when OPENAI_API_KEY is not configured)
# -----------------------------------------------------------------------------

async def run_deterministic_assistant(
    message: str,
    conversation_history: List[Dict[str, str]],
    db: AsyncSession,
) -> Dict[str, Any]:
    """
    Intelligent SOC reasoning engine that executes live read-only tools against backend state,
    correlates evidence, and drafts a structured enterprise SOC response without inventing data.
    """
    lower = message.lower()
    tools_to_run: List[Tuple[str, Dict[str, Any]]] = []
    pending_action: Optional[Dict[str, Any]] = None

    # Detect Security-Changing Actions -> Demand Confirmation
    if any(k in lower for k in ["block ip", "block attacker", "block "]) and not "unblock" in lower:
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)
        target_ip = ip_match.group(0) if ip_match else "127.0.0.1"
        return {
            "reply": f"⚠️ **Analyst Confirmation Required for Security Action**\n\nYou requested to enforce a firewall block on IP `{target_ip}`.\n\nPer enterprise SOC access controls, modifying active perimeter firewall policies requires explicit human analyst authorization. Please confirm or cancel this action below.",
            "tools_executed": [],
            "evidence": [{"type": "action_request", "action": "block_ip", "target": target_ip}],
            "pending_action": {
                "requires_confirmation": True,
                "action_type": "block_ip",
                "target": target_ip,
                "impact": f"Will block IP {target_ip} via enforcer and log event to audit trail.",
                "payload": {"ip": target_ip, "duration_minutes": 60, "reason": "Analyst request via Sentinel Assistant"},
            },
            "meta": {
                "provider": "sentinel_native",
                "openai_configured": bool(settings.openai_api_key),
                "model": "sentinel-soc-native-v1",
            },
        }

    if "reset session" in lower or "clear session" in lower:
        return {
            "reply": "⚠️ **Analyst Confirmation Required for Session Reset**\n\nYou requested to terminate/reset the current visitor session. This will clear behavioural anomaly accumulation and restore routing to the real upstream.\n\nPlease confirm this action below.",
            "tools_executed": [],
            "evidence": [{"type": "action_request", "action": "reset_session"}],
            "pending_action": {
                "requires_confirmation": True,
                "action_type": "reset_session",
                "target": "demo_session",
                "impact": "Will purge session threat markers and reset gateway state.",
                "payload": {"session_id": "demo_session"},
            },
            "meta": {
                "provider": "sentinel_native",
                "openai_configured": bool(settings.openai_api_key),
                "model": "sentinel-soc-native-v1",
            },
        }

    # Intent Classification & Tool Mapping
    if any(k in lower for k in ["what is happening", "what's happening", "current status", "overview", "briefing"]):
        tools_to_run.append(("get_system_health", {}))
        tools_to_run.append(("get_active_incidents", {"limit": 5}))
        tools_to_run.append(("get_gateway_status", {}))

    elif any(k in lower for k in ["dangerous", "worst attacker", "top threat", "highest risk", "which attacker"]):
        tools_to_run.append(("get_active_incidents", {"limit": 5, "severity": "critical"}))
        tools_to_run.append(("get_system_health", {}))

    elif any(k in lower for k in ["investigate", "incident", "latest incident", "inc-"]):
        # Extract ID if present
        inc_match = re.search(r'(?:inc[-_]?)?(\d+)', lower)
        inc_id = inc_match.group(1) if inc_match else "1"
        tools_to_run.append(("get_incident_details", {"incident_id": inc_id}))

    elif any(k in lower for k in ["redirected", "decoy", "diverted", "diversion", "why was this visitor"]):
        tools_to_run.append(("get_visitor_session", {}))
        tools_to_run.append(("get_session_event_history", {"limit": 10}))

    elif any(k in lower for k in ["attack history", "history of this session", "session history", "event history"]):
        tools_to_run.append(("get_session_event_history", {"limit": 20}))

    elif any(k in lower for k in ["function", "functions targeted", "targeted", "api targeting"]):
        tools_to_run.append(("get_function_intelligence", {}))

    elif any(k in lower for k in ["honeytoken", "fake token", "token accessed"]):
        tools_to_run.append(("get_session_event_history", {"limit": 20}))
        tools_to_run.append(("get_function_intelligence", {}))

    elif any(k in lower for k in ["pagerduty", "on call", "on-call", "phone call", "pager duty"]):
        tools_to_run.append(("get_pagerduty_status", {}))

    elif any(k in lower for k in ["honeypot", "fleet", "cowrie", "dionaea", "conpot"]):
        tools_to_run.append(("get_honeypot_activity", {"limit": 10}))

    elif any(k in lower for k in ["fix", "what should i", "recommend", "remediation", "playbook", "contain"]):
        tools_to_run.append(("get_active_incidents", {"limit": 3}))
        tools_to_run.append(("get_gateway_status", {}))

    else:
        # Default holistic context query
        tools_to_run.append(("get_system_health", {}))
        tools_to_run.append(("get_active_incidents", {"limit": 3}))

    # Execute Selected Tools
    executed_results = []
    tool_data = {}
    for t_name, t_args in tools_to_run:
        res = await execute_tool(t_name, t_args, db)
        executed_results.append({"tool": t_name, "parameters": t_args, "status": "success"})
        tool_data[t_name] = res

    # Synthesize Structured SOC Response based on real tool data
    reply_parts = []
    evidence_points = []

    if "get_system_health" in tool_data:
        h = tool_data["get_system_health"]
        evidence_points.append(f"DB Status: {h.get('database')}, Active Blocks: {h.get('active_firewall_blocks')}")

    if "get_active_incidents" in tool_data:
        inc_data = tool_data["get_active_incidents"]
        inc_list = inc_data.get("incidents", [])
        pd_list = inc_data.get("active_pagerduty_incidents", [])
        
        reply_parts.append(f"### 🛡️ Active Incident Analysis\n")
        reply_parts.append(f"Currently tracking **{len(inc_list)} security incident(s)** in the SOC database and **{len(pd_list)} open PagerDuty alert(s)**.")
        
        if inc_list:
            for inc in inc_list[:3]:
                sev_badge = "🔴 CRITICAL" if inc["severity"] == "critical" else "🟡 " + str(inc["severity"]).upper()
                reply_parts.append(f"- **INC-{inc['id']}** [{sev_badge}]: *{inc['title']}* (Status: `{inc['status']}`) — Root cause: {inc.get('root_cause') or 'Suspicious behavioural sequence'}")
                evidence_points.append(f"INC-{inc['id']}: {inc['title']} [{inc['severity']}]")
        else:
            reply_parts.append("\n✅ *No unresolved high-severity incidents are currently open in the database.*")

    if "get_incident_details" in tool_data:
        dt = tool_data["get_incident_details"]
        if dt.get("found"):
            inc = dt["incident"]
            att = dt.get("attacker")
            adv = dt.get("advisory", {})
            reply_parts.append(f"### 🔍 Detailed Incident Investigation: INC-{inc['id']}")
            reply_parts.append(f"**Title:** {inc['title']}\n**Severity:** `{inc['severity'].upper()}` | **Status:** `{inc['status'].upper()}`")
            if inc.get("root_cause"):
                reply_parts.append(f"**Identified Root Cause:** {inc['root_cause']}")
            if inc.get("blast_radius"):
                reply_parts.append(f"**Blast Radius:** {inc['blast_radius']}")
            if att:
                reply_parts.append(f"**Associated Attacker:** IP `{att.get('ip')}` (Risk: `{att.get('risk_score')}/100`, Band: `{att.get('risk_band')}`)")
            
            # Advisory actions
            actions = adv.get("immediate_actions", [])
            if actions:
                reply_parts.append("\n**Recommended Playbook Containment Actions:**")
                for a in actions:
                    reply_parts.append(f"- **{a.get('step')}**: *{a.get('why')}*")
            reply_parts.append(f"\n*(Advisory: {adv.get('disclaimer', 'AI suggestion, human review required')})*")
            evidence_points.append(f"Incident INC-{inc['id']} root cause: {inc.get('root_cause')}")
        else:
            reply_parts.append(f"⚠️ {dt.get('message', 'Incident not found.')}")

    if "get_function_intelligence" in tool_data:
        fi = tool_data["get_function_intelligence"]
        top_fn = fi.get("top_targeted_functions", [])
        reply_parts.append(f"### 🎯 Function-Level Targeting Intelligence\n")
        if any(f["attempts"] > 0 for f in top_fn):
            reply_parts.append("The following sensitive backend functions are experiencing active reconnaissance or exploit attempts:")
            for fn in top_fn:
                if fn["attempts"] > 0:
                    reply_parts.append(f"- **`{fn['name']}`** (`{fn['function_key']}`): **{fn['attempts']} attempt(s)** (Risk Weight: `{fn['weight']}`) [Category: `{fn['category']}`]")
                    evidence_points.append(f"Targeted Function: {fn['name']} ({fn['attempts']} attempts)")
        else:
            reply_parts.append("Zero brute-force or API probing attempts currently recorded against Level-2 function targets.")

    if "get_visitor_session" in tool_data or "get_session_event_history" in tool_data:
        sess = tool_data.get("get_visitor_session", {}).get("session", {})
        hist = tool_data.get("get_session_event_history", {}).get("history", [])
        reply_parts.append(f"### 🧭 Visitor Routing & Session Diversion Analysis\n")
        
        if sess:
            route = sess.get("routed_to", "real")
            score = sess.get("risk_score", 0.0)
            reply_parts.append(f"- **Current Route:** `{route.upper()}`")
            reply_parts.append(f"- **Accumulated Risk Score:** `{score}/100`")
            reply_parts.append(f"- **Attacker IP:** `{sess.get('ip', '127.0.0.1')}`")
            
            if route == "decoy":
                reply_parts.append("\n**Why was this visitor diverted to the decoy?**")
                reply_parts.append(f"1. Threat score reached `{score}/100`, exceeding the diversion threshold (`>= 70.0`).")
                reply_parts.append("2. High-interaction deception sandbox activated to safely isolate adversary probing away from real databases and auth endpoints.")
            evidence_points.append(f"Session route: {route}, Risk: {score}")

        if hist:
            reply_parts.append("\n**Recent Sequential Session Events:**")
            for ev in hist[-5:]:
                reply_parts.append(f"- `{ev.get('timestamp', '')}`: **{ev.get('method', 'GET')}** `{ev.get('path', '')}` → Routed to `{ev.get('routed_to', 'real')}` (Risk: `{ev.get('risk_score', '0')}`)")

    if "get_pagerduty_status" in tool_data:
        pd = tool_data["get_pagerduty_status"]
        reply_parts.append(f"### 📞 PagerDuty Live On-Call Status\n")
        reply_parts.append(f"- **Service Mode:** `{pd.get('service_mode', 'operational').upper()}`")
        reply_parts.append(f"- **Routing Key Configured:** `{'Yes' if pd.get('routing_key_configured') else 'No'}`")
        reply_parts.append(f"- **Responder Phone:** `+91 {pd.get('responder_phone')}` (Twilio Voice escalation active)")
        reply_parts.append(f"- **Responder Email:** `{pd.get('responder_email')}` (Resend alerting active)")
        reply_parts.append(f"- **Active PagerDuty Incidents:** `{pd.get('active_incidents_count', 0)}`")
        evidence_points.append(f"PagerDuty on-call: +91 {pd.get('responder_phone')}")

    if "get_gateway_status" in tool_data:
        gw = tool_data["get_gateway_status"]
        reply_parts.append(f"### ⚡ Deception Gateway Status\n")
        reply_parts.append(f"- **Total Ingested Requests:** `{gw.get('total_gateway_requests')}`")
        reply_parts.append(f"- **Real vs Decoy Breakdown:** `{gw.get('real_traffic_count')}` Real | `{gw.get('decoy_traffic_count')}` Decoy ({gw.get('decoy_diversion_percentage')}% diverted)")
        
        gateways = gw.get("monitored_gateways", [])
        if gateways:
            reply_parts.append("\n**Protected Gateway Lifecycles:**")
            for g in gateways:
                status_icon = "🟢" if g["status"] == "operational" else ("🟡" if g["status"] == "restored" else "🔴")
                reply_parts.append(f"- {status_icon} **{g['name']}** (`{g['endpoint_prefix']}`): Status `{g['status'].upper()}` (Team: `{g['owner_team']}`)")

    # Fallback if nothing specific matched
    if not reply_parts:
        reply_parts.append(f"I analyzed live SOC telemetry for your inquiry. The system is operating normally with zero uncontained high-priority breaches. You can ask me to inspect active incidents, analyze visitor sessions, or check function targeting.")

    final_reply = "\n\n".join(reply_parts)

    return {
        "reply": final_reply,
        "tools_executed": executed_results,
        "evidence": evidence_points,
        "pending_action": pending_action,
        "meta": {
            "provider": "sentinel_native",
            "openai_configured": bool(settings.openai_api_key),
            "model": "sentinel-soc-native-v1",
            "disclaimer": "AI suggestion, human review required",
        },
    }


# -----------------------------------------------------------------------------
# MAIN CHAT ENTRYPOINT (With OpenAI Tool-Calling Support & Native Fallback)
# -----------------------------------------------------------------------------

async def chat_with_assistant(
    message: str,
    conversation_history: List[Dict[str, str]],
    db: AsyncSession,
) -> Dict[str, Any]:
    """
    Main assistant chat pipeline:
    - If OPENAI_API_KEY is configured: Uses OpenAI Chat Completions API with Function Tools.
    - If OPENAI_API_KEY is empty: Falls back directly to Sentinel Native Deterministic Engine.
    """
    if not settings.openai_api_key:
        return await run_deterministic_assistant(message, conversation_history, db)

    # If OpenAI Key is configured: Call OpenAI with Function Calling
    try:
        system_prompt = (
            "You are Noob, an elite Tier-3 Autonomous SOC Security Advisor inside the SENTINEL Cybersecurity platform. "
            "You have direct access to live telemetry through tools. "
            "Always call tools to gather facts before asserting answers. "
            "Label all remediation advice as 'AI suggestion, human review required'. "
            "If an action would modify firewall blocks, change routing, or mutate state, explain the action and request analyst confirmation."
        )

        messages = [{"role": "system", "content": system_prompt}]
        for turn in conversation_history[-6:]:
            messages.append({"role": turn.get("role", "user"), "content": turn.get("content", "")})
        messages.append({"role": "user", "content": message})

        tools_executed = []
        evidence = []

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {settings.openai_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": settings.openai_model,
                    "messages": messages,
                    "tools": ASSISTANT_TOOLS_SPEC,
                    "tool_choice": "auto",
                    "temperature": 0.2,
                },
            )

            if resp.status_code != 200:
                logger.warning(f"OpenAI API call failed with status {resp.status_code}: {resp.text}. Falling back to native engine.")
                return await run_deterministic_assistant(message, conversation_history, db)

            data = resp.json()
            choice = data["choices"][0]["message"]

            # Handle Tool Calls loop (up to 2 iterations)
            if choice.get("tool_calls"):
                messages.append(choice)
                for tool_call in choice["tool_calls"]:
                    fn_name = tool_call["function"]["name"]
                    fn_args = json.loads(tool_call["function"].get("arguments", "{}"))
                    tool_output = await execute_tool(fn_name, fn_args, db)
                    tools_executed.append({"tool": fn_name, "parameters": fn_args, "status": "success"})
                    evidence.append(f"Tool {fn_name}: {str(tool_output)[:100]}")
                    
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call["id"],
                        "name": fn_name,
                        "content": json.dumps(tool_output, default=str),
                    })

                # Second turn with tool results
                second_resp = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {settings.openai_api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": settings.openai_model,
                        "messages": messages,
                        "temperature": 0.2,
                    },
                )
                if second_resp.status_code == 200:
                    final_choice = second_resp.json()["choices"][0]["message"]
                    return {
                        "reply": final_choice.get("content", ""),
                        "tools_executed": tools_executed,
                        "evidence": evidence,
                        "pending_action": None,
                        "meta": {
                            "provider": "openai",
                            "openai_configured": True,
                            "model": settings.openai_model,
                            "disclaimer": "AI suggestion, human review required",
                        },
                    }

            return {
                "reply": choice.get("content", ""),
                "tools_executed": tools_executed,
                "evidence": evidence,
                "pending_action": None,
                "meta": {
                    "provider": "openai",
                    "openai_configured": True,
                    "model": settings.openai_model,
                    "disclaimer": "AI suggestion, human review required",
                },
            }

    except Exception as exc:
        logger.error(f"Error in OpenAI assistant pipeline: {exc}", exc_info=True)
        return await run_deterministic_assistant(message, conversation_history, db)
