from __future__ import annotations
from datetime import datetime, timezone
import logging
from typing import List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.models import ActionLog, Attacker, Incident, ResponseAction
from app.services.audit import record_audit
from app.services.broadcast import broadcast
from app.services.enforcer import request_block
from app.services.notifications import route_and_dispatch_notification

logger = logging.getLogger(__name__)


async def _has_action(db: AsyncSession, attacker_id: int, action_type: str) -> bool:
    stmt = select(ActionLog).where(
        ActionLog.attacker_id == attacker_id,
        ActionLog.action_type == action_type,
    )
    res = await db.execute(stmt)
    return res.scalar_one_or_none() is not None


async def _record_action(
    db: AsyncSession,
    attacker_id: int,
    action_type: str,
    level: int,
    details: dict,
) -> None:
    log = ActionLog(
        attacker_id=attacker_id,
        action_type=action_type,
        level=level,
        details=details,
    )
    db.add(log)
    await db.flush()


async def run_action_ladder(db: AsyncSession, attacker: Attacker) -> List[str]:
    actions_taken: List[str] = []
    band = attacker.risk_band
    score = attacker.risk_score
    now = datetime.now(timezone.utc)

    # Level 1 (<= 25): log
    if not await _has_action(db, attacker.id, "log"):
        await _record_action(db, attacker.id, "log", 1, {
            "message": f"Attacker {attacker.ip} telemetry logged. Initial risk: {score:.0f}",
        })
        actions_taken.append("log")

    # Level 2 (26-50): watchlist
    if band in ("medium", "high", "critical"):
        if not await _has_action(db, attacker.id, "watchlist"):
            if attacker.status != "blocked":
                attacker.status = "watchlist"
            await _record_action(db, attacker.id, "watchlist", 2, {
                "message": f"Attacker {attacker.ip} placed on active watchlist",
            })
            actions_taken.append("watchlist")

    # Level 3 (51-75): notify + recommend
    if band in ("high", "critical"):
        if not await _has_action(db, attacker.id, "notify"):
            await _record_action(db, attacker.id, "notify", 3, {
                "message": f"High risk threshold reached: {attacker.ip} ({score:.0f})",
                "recommendation": "Review attacker telemetry and stage containment block",
            })
            actions_taken.append("notify")
            try:
                await route_and_dispatch_notification(
                    db=db,
                    attacker=attacker,
                    severity="high",
                    title=f"High Risk Alert: {attacker.ip}",
                    message=f"Attacker {attacker.ip} reached high risk velocity ({score:.0f}/100) on decoys: {list(attacker.honeypots_touched or [])}",
                )
                await broadcast("notify", {
                    "ip": attacker.ip,
                    "risk_score": score,
                    "risk_band": band,
                    "recommendation": "Review attacker telemetry and stage containment block",
                })
            except Exception as e:
                logger.warning(f"Failed to route high risk notification: {e}")

    # Level 4 (>= 76): create incident, trigger AI investigation, and propose / execute temp block
    if band == "critical":
        incident_id: int | None = None
        if not await _has_action(db, attacker.id, "incident"):
            # Create incident
            incident = Incident(
                attacker_id=attacker.id,
                title=f"Critical Threat Incident: {attacker.ip}",
                status="new",
                status_history=[{
                    "status": "new",
                    "ts": now.isoformat(),
                    "note": f"Incident triggered by automated risk ladder (score {score:.0f})",
                }],
                root_cause={
                    "contributing_events": [attacker.ip],
                    "factors": [f.get("factor") for f in (attacker.risk_factors or [])],
                },
                blast_radius={
                    "honeypots": list(attacker.honeypots_touched or []),
                    "ports": list(attacker.ports or []),
                    "decoys": ["internal"] if "internal" in str(attacker.intent_evidence) else ["external"],
                    "internal_decoy": "internal" in str(attacker.intent_evidence) or "lateral_movement" == attacker.intent,
                },
                risk_score_at_creation=score,
            )
            if attacker.first_seen:
                t1 = attacker.first_seen if attacker.first_seen.tzinfo else attacker.first_seen.replace(tzinfo=timezone.utc)
                incident.ttd_seconds = round(abs((now - t1).total_seconds()), 2)

            db.add(incident)
            await db.flush()
            incident_id = incident.id

            await _record_action(db, attacker.id, "incident", 4, {
                "incident_id": incident.id,
                "message": f"Incident #{incident.id} spawned for {attacker.ip}",
            })
            actions_taken.append("incident")

            # Route critical notification
            try:
                await route_and_dispatch_notification(
                    db=db,
                    attacker=attacker,
                    severity="critical",
                    title=f"Critical Breach Threat: {attacker.ip}",
                    message=f"Incident #{incident.id} created for {attacker.ip}. Risk: {score:.0f}/100. Intent: {attacker.intent}.",
                    details={"incident_id": incident.id, "blast_radius": incident.blast_radius},
                )
                await broadcast("incident", {
                    "id": incident.id,
                    "title": incident.title,
                    "status": incident.status,
                    "attacker_id": attacker.id,
                    "ip": attacker.ip,
                    "risk_score": score,
                })
            except Exception as e:
                logger.warning(f"Failed to dispatch critical notification: {e}")

            # Trigger AI investigation asynchronously or inline
            try:
                from app.services.ai_investigation import run_ai_investigation
                await run_ai_investigation(db, incident.id)
            except Exception as e:
                logger.warning(f"Initial AI investigation error: {e}")
        else:
            # Look up existing incident id
            stmt_inc = select(Incident.id).where(Incident.attacker_id == attacker.id).order_by(Incident.id.desc()).limit(1)
            incident_id = (await db.execute(stmt_inc)).scalar_one_or_none()

        # Block proposal / automatic execution
        # Auto if risk >= 90 or not REQUIRE_APPROVAL; else propose / manual approval (76-89)
        auto_block = (score >= 90.0) or (not settings.require_approval)
        if auto_block:
            if not await _has_action(db, attacker.id, "block"):
                blk = await request_block(
                    db=db,
                    ip=attacker.ip,
                    attacker_id=attacker.id,
                    ttl_seconds=600,
                    requested_by="system_auto",
                )
                if blk:
                    await _record_action(db, attacker.id, "block", 4, {
                        "block_id": blk.id,
                        "ip": attacker.ip,
                        "ttl_seconds": 600,
                        "mode": "auto",
                    })
                    # Also record in ResponseAction table
                    resp_act = ResponseAction(
                        attacker_id=attacker.id,
                        incident_id=incident_id,
                        block_id=blk.id,
                        action_type="firewall_block",
                        target_ip=attacker.ip,
                        status="verified",
                        reason=f"Automated containment triggered (risk {score:.0f} >= 90)",
                        duration_seconds=600,
                        approver="sentinel_auto",
                        created_at=now,
                        approved_at=now,
                        executed_at=now,
                        verified_at=now,
                        details={"block_id": blk.id, "ttl": 600},
                    )
                    db.add(resp_act)
                    await db.flush()
                    actions_taken.append("block")
                    try:
                        await broadcast("action", {
                            "id": resp_act.id,
                            "action_type": resp_act.action_type,
                            "target_ip": resp_act.target_ip,
                            "status": resp_act.status,
                            "reason": resp_act.reason,
                        })
                    except Exception:
                        pass
        else:
            # Human in the loop approval required
            stmt_act = select(ResponseAction).where(
                ResponseAction.attacker_id == attacker.id,
                ResponseAction.status == "proposed",
            )
            existing_prop = (await db.execute(stmt_act)).scalar_one_or_none()
            if not existing_prop and not await _has_action(db, attacker.id, "propose_block"):
                resp_act = ResponseAction(
                    attacker_id=attacker.id,
                    incident_id=incident_id,
                    action_type="firewall_block",
                    target_ip=attacker.ip,
                    status="proposed",
                    reason=f"Human sign-off required for high-risk adversary (score {score:.0f} in 76-89 band)",
                    duration_seconds=600,
                    approver=None,
                    created_at=now,
                    details={"score": score, "band": band},
                )
                db.add(resp_act)
                await db.flush()

                await _record_action(db, attacker.id, "propose_block", 4, {
                    "ip": attacker.ip,
                    "action_id": resp_act.id,
                    "reason": f"Approval required for risk {score:.0f} (76-89 band)",
                })
                actions_taken.append("propose_block")

                try:
                    await broadcast("action", {
                        "id": resp_act.id,
                        "action_type": resp_act.action_type,
                        "target_ip": resp_act.target_ip,
                        "status": resp_act.status,
                        "reason": resp_act.reason,
                    })
                except Exception:
                    pass

    return actions_taken

