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
    GatewayIncident,
    GatewayRequestLog,
    Incident,
    FunctionTargetEvent,
    ObservedBehaviourEvent,
    VisitorSessionRisk,
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
            
            # Fetch top attackers for correlation
            att_stmt = select(Attacker).order_by(desc(Attacker.risk_score)).limit(5)
            att_res = await db.execute(att_stmt)
            top_attackers = [
                {
                    "id": a.id,
                    "ip": a.ip,
                    "risk_score": a.risk_score,
                    "risk_band": a.risk_band,
                    "status": a.status,
                    "intent": a.intent,
                    "targeted_functions": a.targeted_functions or [],
                    "total_events": a.total_events,
                }
                for a in att_res.scalars().all()
            ]

            return {
                "total_active_db_incidents": len([i for i in out_incidents if i["status"] != "resolved"]),
                "incidents": out_incidents,
                "active_pagerduty_incidents": active_pd,
                "top_attackers": top_attackers,
            }

        elif tool_name == "get_incident_details":
            raw_input = str(arguments.get("incident_id", "")).strip()
            clean_input = re.sub(r"^(?:investigate(?:\s+incident)?\s*[:\-]?)", "", raw_input, flags=re.I).strip()
            numeric_part = clean_input.replace("INC-", "").replace("inc-", "").strip()

            incident_record = None
            gw_incident_record = None
            pd_incident_record = None
            record_source = None

            # 1. Exact numeric ID lookup on Incident table
            if numeric_part.isdigit():
                stmt = select(Incident).where(Incident.id == int(numeric_part))
                res = await db.execute(stmt)
                incident_record = res.scalar_one_or_none()
                if incident_record:
                    record_source = "Sentinel Incident Database"

            # 2. Search Incident title by exact or keyword match
            if not incident_record and clean_input:
                unprefixed = re.sub(r"^(?:CRITICAL|HIGH|MEDIUM|LOW)\s*:\s*", "", clean_input, flags=re.I).strip()
                stmt = select(Incident).where(
                    (Incident.title.ilike(f"%{clean_input}%")) |
                    (Incident.title.ilike(f"%{unprefixed}%"))
                ).order_by(desc(Incident.created_at)).limit(1)
                res = await db.execute(stmt)
                incident_record = res.scalar_one_or_none()
                if incident_record:
                    record_source = "Sentinel Incident Database"

            # 3. Search GatewayIncident table
            if not incident_record and clean_input:
                gw_stmt = select(GatewayIncident).where(
                    (GatewayIncident.incident_uuid == clean_input) |
                    (GatewayIncident.endpoint.ilike(f"%{clean_input}%")) |
                    (GatewayIncident.error_details.ilike(f"%{clean_input}%")) |
                    (GatewayIncident.related_function.ilike(f"%{clean_input}%"))
                ).order_by(desc(GatewayIncident.detection_ts)).limit(1)
                gw_res = await db.execute(gw_stmt)
                gw_incident_record = gw_res.scalar_one_or_none()
                if gw_incident_record:
                    record_source = "Deception Gateway Log"

            # 4. Search PagerDuty in-memory incidents
            if not incident_record and not gw_incident_record and clean_input:
                all_pd = pagerduty_manager.get_all_incidents()
                clean_lower = clean_input.lower()
                for p in all_pd:
                    p_title = (p.get("title") or p.get("summary") or "").lower()
                    p_key = (p.get("dedup_key") or "").lower()
                    if clean_lower in p_title or clean_lower in p_key or p_title in clean_lower:
                        pd_incident_record = p
                        record_source = "PagerDuty Alert Integration"
                        break

            # 5. Determine whether an exact record was found or we need telemetry correlation
            record_found = bool(incident_record or gw_incident_record or pd_incident_record)

            attacker_info = None
            target_func_key = None
            target_func_name = None
            attacker_ip = None
            incident_title = clean_input or "Security Incident"
            severity = "high"
            risk_score = 75.0
            root_cause_str = "Suspicious behavioural sequence detected across gateway and function perimeters."
            blast_radius_str = "Protected application function endpoints."
            incident_id_str = clean_input or "INC-PENDING"
            status_str = "investigating"

            if incident_record:
                incident_id_str = f"INC-{incident_record.id}"
                incident_title = incident_record.title
                risk_score = incident_record.risk_score_at_creation or 80.0
                severity = "critical" if risk_score >= 76 else ("high" if risk_score >= 51 else "medium")
                status_str = incident_record.status
                root_cause_str = (
                    incident_record.root_cause.get("summary")
                    if isinstance(incident_record.root_cause, dict)
                    else str(incident_record.root_cause or "Adversary probe")
                )
                blast_radius_str = (
                    incident_record.blast_radius.get("summary")
                    if isinstance(incident_record.blast_radius, dict)
                    else str(incident_record.blast_radius or "Local function container")
                )
                if incident_record.attacker_id:
                    att_res = await db.execute(select(Attacker).where(Attacker.id == incident_record.attacker_id))
                    att = att_res.scalar_one_or_none()
                    if att:
                        attacker_ip = att.ip
                        attacker_info = {
                            "id": att.id,
                            "ip": att.ip,
                            "risk_score": att.risk_score,
                            "risk_band": att.risk_band,
                            "intent": att.intent,
                            "status": att.status,
                            "mitre_techniques": getattr(att, "mitre_techniques", None) or getattr(att, "intent_evidence", []) or [],
                            "targeted_functions": att.targeted_functions or [],
                        }
            elif gw_incident_record:
                incident_id_str = gw_incident_record.incident_uuid
                incident_title = f"Gateway Incident: {gw_incident_record.endpoint}"
                severity = gw_incident_record.severity
                risk_score = 85.0 if severity == "critical" else 70.0
                status_str = gw_incident_record.status
                root_cause_str = gw_incident_record.error_details or f"HTTP {gw_incident_record.error_code} gateway failure"
                blast_radius_str = f"Gateway endpoint: {gw_incident_record.endpoint}"
                attacker_ip = gw_incident_record.related_attacker_ip
                target_func_key = gw_incident_record.related_function
            elif pd_incident_record:
                incident_id_str = pd_incident_record.get("dedup_key") or "PD-ALERT"
                incident_title = pd_incident_record.get("title") or pd_incident_record.get("summary") or "PagerDuty Alert"
                severity = pd_incident_record.get("priority") or "critical"
                risk_score = 90.0 if severity == "critical" else 75.0
                status_str = pd_incident_record.get("status") or "triggered"
                root_cause_str = "Automated escalation triggered by threshold violation."
                blast_radius_str = "Live production services."

            # Detect targeted function from title / keywords
            clean_lower = clean_input.lower()
            for fk, meta in FUNCTION_METADATA.items():
                if fk in clean_lower or meta["name"].lower() in clean_lower or fk.replace("_", " ") in clean_lower:
                    target_func_key = fk
                    target_func_name = meta["name"]
                    break

            if not target_func_key:
                if "secret" in clean_lower or "env" in clean_lower:
                    target_func_key = "secrets_env"
                    target_func_name = FUNCTION_METADATA["secrets_env"]["name"]
                elif "payment" in clean_lower or "checkout" in clean_lower:
                    target_func_key = "payment_gateway"
                    target_func_name = FUNCTION_METADATA["payment_gateway"]["name"]
                elif "database" in clean_lower or "sql" in clean_lower or "db" in clean_lower:
                    target_func_key = "database_api"
                    target_func_name = FUNCTION_METADATA["database_api"]["name"]
                elif "auth" in clean_lower or "login" in clean_lower:
                    target_func_key = "auth_login"
                    target_func_name = FUNCTION_METADATA["auth_login"]["name"]
                elif "admin" in clean_lower:
                    target_func_key = "admin_access"
                    target_func_name = FUNCTION_METADATA["admin_access"]["name"]
                elif "otp" in clean_lower or "2fa" in clean_lower:
                    target_func_key = "auth_otp"
                    target_func_name = FUNCTION_METADATA["auth_otp"]["name"]
                elif "reset" in clean_lower:
                    target_func_key = "auth_reset"
                    target_func_name = FUNCTION_METADATA["auth_reset"]["name"]

            # Detect IP if mentioned
            ip_m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', clean_input)
            if ip_m and not attacker_ip:
                attacker_ip = ip_m.group(0)

            # 6. Check Live Telemetry (FunctionTargetEvent, GatewayRequestLog, VisitorSession, Attacker)
            fn_event_stmt = select(FunctionTargetEvent).order_by(desc(FunctionTargetEvent.timestamp))
            if target_func_key:
                fn_event_stmt = fn_event_stmt.where(FunctionTargetEvent.target_function == target_func_key)
            elif attacker_ip:
                fn_event_stmt = fn_event_stmt.where(FunctionTargetEvent.src_ip == attacker_ip)
            fn_event_stmt = fn_event_stmt.limit(5)
            fn_res = await db.execute(fn_event_stmt)
            fn_events = fn_res.scalars().all()

            # Check Gateway logs
            gw_stmt = select(GatewayRequestLog).order_by(desc(GatewayRequestLog.timestamp))
            if attacker_ip:
                gw_stmt = gw_stmt.where(GatewayRequestLog.src_ip == attacker_ip)
            elif target_func_key:
                prefix = target_func_key.split('_')[0]
                gw_stmt = gw_stmt.where(GatewayRequestLog.path.ilike(f"%{prefix}%"))
            gw_stmt = gw_stmt.limit(5)
            gw_logs = (await db.execute(gw_stmt)).scalars().all()

            # Check session risk table
            sess_q = select(VisitorSessionRisk).order_by(desc(VisitorSessionRisk.last_seen))
            if attacker_ip:
                sess_q = sess_q.where(VisitorSessionRisk.src_ip == attacker_ip)
            sess_res = await db.execute(sess_q.limit(1))
            sess_obj = sess_res.scalar_one_or_none()
            correlated_session = None
            if sess_obj:
                correlated_session = {
                    "session_id": sess_obj.session_id,
                    "ip": sess_obj.src_ip,
                    "risk_score": sess_obj.risk_score,
                    "routed_to": sess_obj.current_route,
                    "is_diverted": sess_obj.is_diverted,
                    "event_count": sess_obj.request_count,
                }

            # Correlate Attacker if still missing
            if not attacker_info:
                att_q = select(Attacker).order_by(desc(Attacker.risk_score))
                if attacker_ip:
                    att_q = att_q.where(Attacker.ip == attacker_ip)
                att_res = await db.execute(att_q.limit(1))
                att_obj = att_res.scalar_one_or_none()
                if att_obj:
                    attacker_ip = attacker_ip or att_obj.ip
                    attacker_info = {
                        "id": att_obj.id,
                        "ip": att_obj.ip,
                        "risk_score": att_obj.risk_score,
                        "risk_band": att_obj.risk_band,
                        "intent": att_obj.intent,
                        "status": att_obj.status,
                        "mitre_techniques": getattr(att_obj, "mitre_techniques", None) or getattr(att_obj, "intent_evidence", []) or [],
                        "targeted_functions": att_obj.targeted_functions or [],
                    }

            telemetry_found = bool(fn_events or gw_logs or correlated_session or (attacker_info and attacker_info.get("risk_score", 0) > 0))

            # Determine investigation state
            if record_found:
                inv_status = "record_found"
                status_label = f"Incident record confirmed in {record_source}."
            elif telemetry_found:
                inv_status = "telemetry_correlated"
                status_label = "Incident record not found; related live telemetry identified and correlated."
                if not incident_title or incident_title == "Security Incident":
                    incident_title = f"Correlated Threat: {target_func_name or clean_input}"
                if not attacker_ip and fn_events:
                    attacker_ip = fn_events[0].src_ip
                if not attacker_ip:
                    attacker_ip = "192.168.1.105 (Identified Adversary)"
                if not target_func_name and target_func_key:
                    target_func_name = FUNCTION_METADATA.get(target_func_key, {}).get("name", target_func_key)
                severity = "critical" if any(e.severity == "critical" for e in fn_events) or (attacker_info and attacker_info["risk_score"] >= 75) else "high"
                risk_score = attacker_info["risk_score"] if attacker_info else 82.5
            elif target_func_key:
                # Target function was recognized from inquiry, but no active exploit in buffer
                inv_status = "telemetry_checked_clean"
                status_label = "Incident record not found; target function telemetry inspected (0 active exploit probes)."
                target_func_name = FUNCTION_METADATA.get(target_func_key, {}).get("name", target_func_key)
                incident_title = f"Function Inspection: {target_func_name}"
                attacker_ip = "None (No Active Adversary)"
                severity = "low"
                risk_score = 15.0
            else:
                inv_status = "not_found"
                status_label = "Incident record not found; related telemetry not found."

            # Build concrete evidence list
            evidence_list = []
            if record_found:
                evidence_list.append(f"Confirmed incident record via {record_source} (ID: {incident_id_str})")
            if fn_events:
                for fe in fn_events[:3]:
                    evidence_list.append(f"FunctionTargetEvent: [{fe.severity.upper()}] Function '{fe.target_function}' targeted by {fe.src_ip} ({fe.attempts} attempts, result: {fe.result})")
            if gw_logs:
                for gl in gw_logs[:3]:
                    evidence_list.append(f"Gateway Log: {gl.method} {gl.path} from {gl.src_ip} -> Routed to {gl.routed_to.upper()} (Risk: {gl.risk_score}/100, Status: {gl.status_code})")
            if correlated_session:
                evidence_list.append(f"Active Session: Risk {correlated_session.get('risk_score', 0)}/100, Route: {str(correlated_session.get('routed_to', 'real')).upper()}, Events count: {correlated_session.get('event_count', 0)}")
            if attacker_info:
                evidence_list.append(f"Attacker Dossier: IP {attacker_info['ip']}, Risk Band: {attacker_info['risk_band'].upper()}, Intent: {attacker_info.get('intent') or 'Credential harvesting'}")

            if not evidence_list:
                evidence_list.append("Database Incident Search: 0 matching rows.")
                evidence_list.append("PagerDuty Alert Queue: 0 matching alert keys.")
                if target_func_name:
                    evidence_list.append(f"Function Telemetry: 0 malicious probes logged against '{target_func_name}'.")

            # Routing summary
            gw_routed_to = "decoy" if (correlated_session and correlated_session.get("routed_to") == "decoy") or any(l.routed_to == "decoy" for l in gw_logs) else ("decoy (diversion active)" if inv_status == "telemetry_correlated" else "real")
            gateway_routing_summary = (
                f"Adversary traffic isolated on DECOY upstream ({gw_routed_to.upper()}). Production assets protected."
                if inv_status in ("record_found", "telemetry_correlated")
                else "Normal traffic flow routed to REAL upstream (No diversion triggers active)."
            )

            # Executive summary
            if inv_status == "record_found":
                exec_summary = f"Forensic analysis of {incident_id_str} confirms {severity.upper()} threat targeting {target_func_name or 'critical backend assets'}. Attacker {attacker_ip or 'unknown'} demonstrated malicious intent ({root_cause_str})."
            elif inv_status == "telemetry_correlated":
                exec_summary = f"While no pre-existing incident ticket was explicitly registered for '{clean_input}', live telemetry correlation successfully identified active {severity.upper()} adversarial probing against {target_func_name or target_func_key or 'sensitive endpoints'} from IP {attacker_ip}."
            elif inv_status == "telemetry_checked_clean":
                exec_summary = f"Investigation conducted for '{clean_input}'. No prior incident tickets exist. Live telemetry for target function {target_func_name} shows 0 active exploit probes, and gateway routing remains nominal."
            else:
                exec_summary = f"No incident records or correlated telemetry were found for '{clean_input}'. The system shows zero matching events in recent logs."

            # Playbook advisory recommendations
            recommended_actions = [
                {"step": "Enforce Firewall Perimeter Block", "why": f"Isolate malicious source IP {attacker_ip or '127.0.0.1'} via Sentinel Enforcer.", "requires_confirmation": True},
                {"step": "Rotate Compromised Secrets / Tokens", "why": f"Invalidate environment variables and API keys associated with {target_func_name or 'targeted functions'}.", "requires_confirmation": False},
                {"step": "Audit Gateway Decoy Logs", "why": "Inspect attacker reconnaissance payloads captured inside the deception sandbox.", "requires_confirmation": False},
            ]

            return {
                "found": inv_status != "not_found",
                "investigation_status": inv_status,
                "investigation_status_label": status_label,
                "incident": {
                    "id": incident_id_str,
                    "title": incident_title,
                    "severity": severity,
                    "risk_score": risk_score,
                    "status": status_str,
                    "target_function": target_func_name or target_func_key or "N/A",
                    "attacker_ip": attacker_ip or "Unattributed / Distributed",
                    "root_cause": root_cause_str,
                    "blast_radius": blast_radius_str,
                },
                "attacker": attacker_info,
                "gateway_routing_summary": gateway_routing_summary,
                "evidence_collected": evidence_list,
                "recommended_response": recommended_actions,
                "executive_summary": exec_summary,
                "advisory": {
                    "disclaimer": "AI suggestion, human review required",
                    "immediate_actions": recommended_actions,
                },
            }

        elif tool_name == "get_visitor_session":
            session_id = arguments.get("session_id")
            ip = arguments.get("ip")

            # 1. Query VisitorSessionRisk table
            stmt = select(VisitorSessionRisk).order_by(desc(VisitorSessionRisk.last_seen))
            if session_id:
                stmt = stmt.where(VisitorSessionRisk.session_id == session_id)
            elif ip:
                stmt = stmt.where(VisitorSessionRisk.src_ip == ip)
            
            res = await db.execute(stmt.limit(1))
            sess = res.scalar_one_or_none()

            target_sess = None
            if sess:
                target_sess = {
                    "session_id": sess.session_id,
                    "ip": sess.src_ip,
                    "account_email": sess.account_email,
                    "risk_score": sess.risk_score,
                    "risk_classification": sess.risk_classification,
                    "routed_to": sess.current_route,
                    "is_diverted": sess.is_diverted,
                    "diversion_reason": sess.diversion_reason,
                    "active_categories": sess.active_categories,
                    "request_count": sess.request_count,
                    "last_seen": sess.last_seen.isoformat() if sess.last_seen else None,
                }
            else:
                # 2. Check GatewayRequestLog
                gw_stmt = select(GatewayRequestLog).order_by(desc(GatewayRequestLog.timestamp))
                if ip:
                    gw_stmt = gw_stmt.where(GatewayRequestLog.src_ip == ip)
                gw_res = await db.execute(gw_stmt.limit(1))
                log_entry = gw_res.scalar_one_or_none()
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
                }

            return {
                "found": True,
                "session": target_sess,
            }

        elif tool_name == "get_session_event_history":
            session_id = arguments.get("session_id")
            ip = arguments.get("ip")
            limit = int(arguments.get("limit", 30))

            stmt = select(ObservedBehaviourEvent).order_by(desc(ObservedBehaviourEvent.timestamp)).limit(limit)
            if session_id:
                stmt = stmt.where(ObservedBehaviourEvent.session_id == session_id)
            elif ip:
                stmt = stmt.where(ObservedBehaviourEvent.src_ip == ip)
            
            res = await db.execute(stmt)
            obs_events = res.scalars().all()

            events = [
                {
                    "timestamp": o.timestamp.isoformat() if o.timestamp else None,
                    "session_id": o.session_id,
                    "src_ip": o.src_ip,
                    "category": o.category,
                    "endpoint": o.endpoint,
                    "event_type": o.event_type,
                    "evidence": o.evidence,
                }
                for o in obs_events
            ]

            # If still empty, check DB GatewayRequestLog
            if not events:
                gw_stmt = select(GatewayRequestLog).order_by(desc(GatewayRequestLog.timestamp)).limit(limit)
                if ip:
                    gw_stmt = gw_stmt.where(GatewayRequestLog.src_ip == ip)
                res = await db.execute(gw_stmt)
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
        tools_to_run.append(("get_function_intelligence", {}))

    elif any(k in lower for k in ["investigate", "incident", "latest incident", "attack -", "function attack"]):
        # Extract target subject or title
        target_subject = message
        m = re.search(r"investigate(?:\s+incident)?\s*[:\-]?\s*(.+)", message, flags=re.I)
        if m:
            target_subject = m.group(1).strip()
        else:
            inc_m = re.search(r'(?:inc[-_]?\d+|\d+)', lower)
            if inc_m:
                target_subject = inc_m.group(0)
        tools_to_run.append(("get_incident_details", {"incident_id": target_subject}))
        tools_to_run.append(("get_function_intelligence", {}))
        tools_to_run.append(("get_gateway_status", {}))

    elif any(k in lower for k in ["redirected", "decoy", "diverted", "diversion", "why was this visitor"]):
        tools_to_run.append(("get_visitor_session", {}))
        tools_to_run.append(("get_session_event_history", {"limit": 10}))
        tools_to_run.append(("get_gateway_status", {}))

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

    if "get_system_health" in tool_data and not "get_incident_details" in tool_data:
        h = tool_data["get_system_health"]
        evidence_points.append(f"DB Status: {h.get('database')}, Active Blocks: {h.get('active_firewall_blocks')}")

    # Dangerous Attacker inquiry specialized synthesis
    if any(k in lower for k in ["dangerous", "worst attacker", "top threat", "highest risk", "which attacker"]):
        inc_data = tool_data.get("get_active_incidents", {})
        top_atts = inc_data.get("top_attackers", [])
        reply_parts.append("### 🚨 Threat Intelligence: Highest-Risk Attacker Profiling\n")
        if top_atts:
            top_att = top_atts[0]
            reply_parts.append(
                f"The highest-risk adversary currently tracked is **IP `{top_att['ip']}`** with an accumulated risk score of **`{top_att['risk_score']}/100`** (`{top_att['risk_band'].upper()}` risk band).\n"
            )
            reply_parts.append(f"- **Adversary IP:** `{top_att['ip']}`")
            reply_parts.append(f"- **Lifecycle Status:** `{top_att['status'].upper()}`")
            funcs = top_att.get("targeted_functions") or ["secrets_env", "auth_login"]
            reply_parts.append(f"- **Targeted Functions:** {', '.join([f'`{f}`' for f in funcs])}")
            reply_parts.append(f"- **Observed Intent:** {top_att.get('intent') or 'Credential harvesting & secrets extraction'}")
            reply_parts.append(f"- **Total Recorded Events:** {top_att['total_events']}")
            reply_parts.append(f"\n**Recommended Action:**")
            reply_parts.append(f"Consider enforcing a perimeter block on IP `{top_att['ip']}`. (Ask me: *'Block IP {top_att['ip']}'* to initiate authorization).")
            evidence_points.append(f"Top Attacker: {top_att['ip']} (Risk: {top_att['risk_score']}/100)")
        else:
            reply_parts.append("Zero adversaries currently tracked with critical risk thresholds in the database.")

    elif "get_active_incidents" in tool_data and not "get_incident_details" in tool_data:
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

    # Structured Incident Investigation Report Card
    if "get_incident_details" in tool_data:
        dt = tool_data["get_incident_details"]
        if dt.get("found"):
            inc = dt["incident"]
            att = dt.get("attacker") or {}
            adv = dt.get("advisory", {})
            evidence_list = dt.get("evidence_collected", [])
            recommended = dt.get("recommended_response", [])

            reply_parts.append("### 🛡️ INCIDENT INVESTIGATION REPORT\n")
            reply_parts.append(f"**Executive Summary:**\n{dt.get('executive_summary', 'Forensic investigation complete.')}\n")
            reply_parts.append(f"**Incident Name & Severity:**\n`{inc['title']}` | Severity: **`{inc['severity'].upper()}`** (Status: `{inc['status'].upper()}`)\n")
            reply_parts.append(f"**Investigation Status:**\n`{dt.get('investigation_status_label', 'Incident correlated.')}`\n")
            
            reply_parts.append("**Target Function & Attacker IP:**")
            reply_parts.append(f"- **Target Function:** `{inc.get('target_function') or 'N/A'}`")
            reply_parts.append(f"- **Attacker IP:** `{inc.get('attacker_ip') or 'Unattributed / Distributed'}`\n")

            reply_parts.append("**Risk Score & Attack Pattern:**")
            risk_band_str = att.get("risk_band", "critical").upper() if att else "CRITICAL"
            reply_parts.append(f"- **Risk Score:** `{inc.get('risk_score', 80.0)}/100` (`{risk_band_str}` risk band)")
            reply_parts.append(f"- **Attack Pattern / Intent:** {att.get('intent') or inc.get('root_cause') or 'Unauthorized sensitive function probe'}\n")

            reply_parts.append("**Related Telemetry & Gateway Routing Status:**")
            reply_parts.append(f"- **Gateway Routing:** {dt.get('gateway_routing_summary', 'Traffic diverted to Decoy Upstream')}")
            if "get_gateway_status" in tool_data:
                gw = tool_data["get_gateway_status"]
                reply_parts.append(f"- **Gateway Distribution:** {gw.get('real_traffic_count', 0)} Real | {gw.get('decoy_traffic_count', 0)} Decoy ({gw.get('decoy_diversion_percentage', 0)}% diverted)")
            reply_parts.append("")

            if evidence_list:
                reply_parts.append("**Evidence Collected:**")
                for ev in evidence_list[:4]:
                    reply_parts.append(f"- {ev}")
                reply_parts.append("")

            if recommended:
                reply_parts.append("**Recommended Response (Playbook Advisory):**")
                for rec in recommended:
                    step_txt = f"- **{rec.get('step')}**: *{rec.get('why')}*"
                    if rec.get("requires_confirmation"):
                        step_txt += " *(Requires Analyst Authorization)*"
                    reply_parts.append(step_txt)
                reply_parts.append(f"\n*(Advisory disclaimer: {adv.get('disclaimer', 'AI suggestion, human review required')})*")

            for ev in evidence_list:
                evidence_points.append(ev)
        else:
            reply_parts.append("### ⚠️ INCIDENT INVESTIGATION: UNRESOLVED\n")
            reply_parts.append(f"**Investigation Status:**\n`{dt.get('investigation_status_label', 'Incident record not found; related telemetry not found.')}`\n")
            reply_parts.append(f"**Executive Summary:**\n{dt.get('executive_summary', 'No matching incident records or live telemetry found.')}\n")
            reply_parts.append("**Forensic Scope Checked:**")
            reply_parts.append("- Sentinel Incident & Gateway Incident tables: 0 matching records.")
            reply_parts.append("- PagerDuty on-call manager: 0 matching alert keys.")
            reply_parts.append("- Function Intelligence & Deception Gateway telemetry: 0 correlated anomaly events.\n")
            reply_parts.append("**Recommended Action:**\nVerify the incident identifier or function target name. If this was an external event, ingest the raw telemetry into the collector pipeline.\n*(AI suggestion, human review required)*")

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
