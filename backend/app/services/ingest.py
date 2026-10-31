from __future__ import annotations
from datetime import datetime, timezone, timedelta
import logging
from typing import Any, Dict, List
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import Attacker, Event, Relationship
from app.schemas import EventIn
from app.services.actions import run_action_ladder
from app.services.anomaly import predict_anomaly, retrain_if_needed
from app.services.broadcast import broadcast
from app.services.classify import classify_event
from app.services.correlate import find_and_store_relationships
from app.services.dedup import get_or_create_alert
from app.services.enrich import enrich_ip
from app.services.fingerprint import compute_fingerprint
from app.services.integrity import compute_chain_hash_for_event, compute_raw_hash
from app.services.intent import classify_intent
from app.services.killchain import update_killchain_for_attacker
from app.services.mitre import update_mitre_for_attacker
from app.services.normalise import normalise_event
from app.services.risk import compute_risk
from app.services.function_intelligence import map_event_to_function, record_function_targeting

logger = logging.getLogger(__name__)


def _append_unique(lst: list, item: Any) -> list:
    if item is not None and item != "" and item not in lst:
        lst.append(item)
    return lst


async def get_or_create_attacker(db: AsyncSession, ip: str, now: datetime) -> Attacker:
    stmt = select(Attacker).where(Attacker.ip == ip)
    res = await db.execute(stmt)
    attacker = res.scalar_one_or_none()

    if not attacker:
        attacker = Attacker(
            ip=ip,
            first_seen=now,
            last_seen=now,
            total_events=0,
            honeypots_touched=[],
            ports=[],
            usernames=[],
            passwords=[],
            commands=[],
            urls=[],
            hashes=[],
            sessions=[],
            is_repeat=False,
            status="active",
            risk_score=0.0,
            risk_band="low",
            risk_factors=[],
            risk_history=[],
            intent="reconnaissance",
            intent_evidence=[],
        )
        db.add(attacker)
        await db.flush()

    return attacker


async def ingest_event(db: AsyncSession, event_in: EventIn) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)

    # 1. Deduplicate by event_id: ignore duplicate
    stmt = select(Event.id).where(Event.event_id == event_in.event_id)
    existing_id = (await db.execute(stmt)).scalar_one_or_none()
    if existing_id:
        return {"status": "ignored_duplicate", "event_id": event_in.event_id}

    # 2. Normalise
    norm = normalise_event(event_in)
    event_type = norm["event_type"]
    honeypot = norm["honeypot"]
    decoy_type = norm["decoy_type"]
    command = norm["command"]
    username = norm["username"]
    password = norm["password"]
    url = norm["url"]

    # 3. Get / create attacker per src_ip (never merge different IPs)
    attacker = await get_or_create_attacker(db, event_in.src_ip, now)
    attacker.last_seen = now
    attacker.total_events += 1

    # Update metadata lists
    hp_list = list(attacker.honeypots_touched or [])
    if honeypot and honeypot not in hp_list:
        hp_list.append(honeypot)
    attacker.honeypots_touched = hp_list

    if event_in.dst_port is not None:
        p_list = list(attacker.ports or [])
        if event_in.dst_port not in p_list:
            p_list.append(event_in.dst_port)
        attacker.ports = p_list

    if username:
        attacker.usernames = _append_unique(list(attacker.usernames or []), username)
    if password:
        attacker.passwords = _append_unique(list(attacker.passwords or []), password)
    if command:
        cmd_list = list(attacker.commands or [])
        cmd_list.append(command)
        attacker.commands = cmd_list
    if url:
        attacker.urls = _append_unique(list(attacker.urls or []), url)
    if event_in.file_hash:
        attacker.hashes = _append_unique(list(attacker.hashes or []), event_in.file_hash)
    if event_in.session_id:
        attacker.sessions = _append_unique(list(attacker.sessions or []), event_in.session_id)

    # 4. Fingerprint computation
    stmt_ts = select(Event.timestamp).where(Event.attacker_id == attacker.id)
    ts_res = await db.execute(stmt_ts)
    all_timestamps = [row[0] for row in ts_res.all()]
    all_timestamps.append(event_in.timestamp)

    fp, fv = compute_fingerprint(
        commands=list(attacker.commands or []),
        usernames=list(attacker.usernames or []),
        passwords=list(attacker.passwords or []),
        event_timestamps=all_timestamps,
    )

    # Check if repeat attacker: same fingerprint as another IP profile
    if fp and fp != attacker.fingerprint:
        stmt_repeat = select(Attacker.id).where(
            Attacker.fingerprint == fp,
            Attacker.ip != attacker.ip,
        ).limit(1)
        rep_res = await db.execute(stmt_repeat)
        if rep_res.scalar_one_or_none():
            attacker.is_repeat = True

    attacker.fingerprint = fp
    attacker.feature_vector = fv

    # 5. Classify event
    classification = await classify_event(
        db=db,
        event_type=event_type,
        src_ip=event_in.src_ip,
        decoy_type=decoy_type,
        command=command,
        honeypot=honeypot,
        attacker_id=attacker.id,
    )

    # 6. Store Event with cryptographic hash chain
    raw_dict = dict(event_in.raw) if event_in.raw else {}
    raw_hash = compute_raw_hash(raw_dict, event_in.event_id)
    chain_hash, prev_hash = await compute_chain_hash_for_event(
        db=db,
        raw_hash=raw_hash,
        event_id=event_in.event_id,
        timestamp_str=event_in.timestamp.isoformat(),
    )

    event_obj = Event(
        event_id=event_in.event_id,
        timestamp=event_in.timestamp,
        received_at=now,
        honeypot=honeypot,
        decoy_type=decoy_type,
        src_ip=event_in.src_ip,
        src_port=event_in.src_port,
        dst_port=event_in.dst_port,
        session_id=event_in.session_id,
        event_type=event_type,
        username=username,
        password=password,
        command=command,
        url=url,
        file_hash=event_in.file_hash,
        raw=raw_dict,
        normalised=norm,
        raw_hash=raw_hash,
        chain_hash=chain_hash,
        prev_hash=prev_hash,
        attacker_id=attacker.id,
    )
    db.add(event_obj)
    await db.flush()

    # 6.1 Level-2 Function-Level Attack Intelligence Mapping
    mapped_target = map_event_to_function(
        event_type=event_type,
        command=command,
        url=url,
        dst_port=event_in.dst_port,
        honeypot=honeypot,
        raw=raw_dict,
    )
    if mapped_target:
        fn_key, fn_endpoint, fn_evidence, fn_confidence, fn_is_inferred = mapped_target
        await record_function_targeting(
            db=db,
            attacker=attacker,
            target_function=fn_key,
            target_endpoint=fn_endpoint,
            attack_type=classification or event_type,
            severity="critical" if fn_key in ("secrets_env", "payment_gateway") else "high" if fn_key in ("admin_access", "database_api") else "medium",
            result="intercepted",
            attempts=1,
            honeypot_source=honeypot,
            evidence=fn_evidence,
            confidence=fn_confidence,
            is_simulated=False,
            event_timestamp=event_in.timestamp,
        )

    # 7. MITRE & Kill Chain mappings
    mitre_list = await update_mitre_for_attacker(
        db=db,
        attacker_id=attacker.id,
        event_uuid=event_in.event_id,
        event_type=event_type,
        command=command,
        decoy_type=decoy_type,
        classification=classification,
    )

    kc_list = await update_killchain_for_attacker(
        db=db,
        attacker_id=attacker.id,
        event_uuid=event_in.event_id,
        event_type=event_type,
        command=command,
        decoy_type=decoy_type,
        classification=classification,
    )

    # 8. Intent classification
    stmt_evs = select(Event.event_type, Event.command, Event.decoy_type).where(Event.attacker_id == attacker.id)
    evs_res = await db.execute(stmt_evs)
    all_evs = evs_res.all()

    all_etypes = [e[0] for e in all_evs]
    all_cmds = [e[1] for e in all_evs if e[1]]
    all_decoys = [e[2] for e in all_evs]

    top_intent, intent_ev = classify_intent(
        event_types=all_etypes,
        commands=all_cmds,
        decoy_types=all_decoys,
        classifications=[classification] if classification else [],
    )
    attacker.intent = top_intent
    attacker.intent_evidence = intent_ev

    # 9. Anomaly detection
    is_anomaly, anomaly_score = predict_anomaly(fv)
    attacker.is_anomaly = is_anomaly
    attacker.anomaly_score = anomaly_score

    # 10. Check if related to another high-risk attacker
    stmt_rels = select(Relationship).where(
        (Relationship.attacker_a_id == attacker.id) | (Relationship.attacker_b_id == attacker.id)
    )
    rel_rows = (await db.execute(stmt_rels)).scalars().all()
    neighbor_ids = set()
    for r in rel_rows:
        neighbor_ids.add(r.attacker_a_id)
        neighbor_ids.add(r.attacker_b_id)
    neighbor_ids.discard(attacker.id)

    related_high_risk = False
    if neighbor_ids:
        stmt_hr = select(Attacker.id).where(
            Attacker.id.in_(neighbor_ids),
            Attacker.risk_score >= 76.0,
        ).limit(1)
        if (await db.execute(stmt_hr)).scalar_one_or_none():
            related_high_risk = True

    # 11. Risk Score computation
    risk_score, risk_factors, risk_band = compute_risk(
        event_types=all_etypes,
        classifications=[classification] if classification else [],
        honeypots_touched=list(attacker.honeypots_touched or []),
        decoy_types=all_decoys,
        is_repeat=attacker.is_repeat,
        is_anomaly=is_anomaly,
        related_high_risk=related_high_risk,
        external_reputation=0.0,
    )

    attacker.risk_score = risk_score
    attacker.risk_band = risk_band
    attacker.risk_factors = risk_factors

    history = list(attacker.risk_history or [])
    history.append({
        "ts": now.isoformat(),
        "score": risk_score,
        "band": risk_band,
    })
    attacker.risk_history = history[-100:]

    # 12. Alert deduplication
    alert, is_new_alert = await get_or_create_alert(
        db=db,
        src_ip=event_in.src_ip,
        event_type=event_type,
        honeypot=honeypot,
        event_uuid=event_in.event_id,
        attacker_id=attacker.id,
        classification=classification,
    )

    # 13. Relationship graph update
    stmt_others = select(Attacker).where(Attacker.id != attacker.id)
    others = (await db.execute(stmt_others)).scalars().all()

    window_10m = now - timedelta(seconds=600)
    stmt_recent = select(Event).where(Event.received_at >= window_10m)
    recent_events = (await db.execute(stmt_recent)).scalars().all()

    new_relationships = await find_and_store_relationships(
        db=db,
        attacker=attacker,
        all_attackers=others,
        recent_events=recent_events,
    )

    # 14. Action ladder execution
    actions_taken = await run_action_ladder(db, attacker)

    # 15. Periodic anomaly retrain
    stmt_count = select(func.count(Attacker.id))
    tot_atks = (await db.execute(stmt_count)).scalar_one() or 0
    if tot_atks >= 30 and tot_atks % 10 == 0:
        await retrain_if_needed(db)

    # 16. WebSocket Broadcasts
    try:
        await broadcast("event", {
            "id": event_obj.id,
            "event_id": event_in.event_id,
            "timestamp": event_in.timestamp.isoformat(),
            "received_at": now.isoformat(),
            "honeypot": honeypot,
            "decoy_type": decoy_type,
            "src_ip": event_in.src_ip,
            "dst_port": event_in.dst_port,
            "event_type": event_type,
            "command": command,
            "username": username,
            "risk_score": risk_score,
            "risk_band": risk_band,
            "classification": classification,
        })

        await broadcast("attacker_update", {
            "id": attacker.id,
            "ip": attacker.ip,
            "risk_score": risk_score,
            "risk_band": risk_band,
            "intent": top_intent,
            "status": attacker.status,
            "total_events": attacker.total_events,
            "is_repeat": attacker.is_repeat,
            "fingerprint": attacker.fingerprint,
            "honeypots_touched": attacker.honeypots_touched,
        })

        for rel in new_relationships:
            await broadcast("relationship", rel)
    except Exception as e:
        logger.warning(f"Broadcast failed: {e}")

    return {
        "status": "ok",
        "event_id": event_in.event_id,
        "attacker_id": attacker.id,
        "risk_score": risk_score,
        "risk_band": risk_band,
        "classification": classification,
        "actions_taken": actions_taken,
        "is_new_alert": is_new_alert,
    }

