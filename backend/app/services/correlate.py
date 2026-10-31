from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List, Set
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import Attacker, Event, Relationship

JACCARD_THRESHOLD = 0.5
SAME_WINDOW_SECONDS = 600  # 10 minutes


def jaccard_similarity(set_a: Set[Any], set_b: Set[Any]) -> float:
    if not set_a or not set_b:
        return 0.0
    intersection = set_a & set_b
    union = set_a | set_b
    return len(intersection) / len(union) if union else 0.0


async def find_and_store_relationships(
    db: AsyncSession,
    attacker: Attacker,
    all_attackers: List[Attacker],
    recent_events: List[Event],
) -> List[Dict[str, Any]]:
    new_edges: List[Dict[str, Any]] = []

    for other in all_attackers:
        if other.id == attacker.id:
            continue

        stmt = select(Relationship).where(
            or_(
                and_(Relationship.attacker_a_id == attacker.id, Relationship.attacker_b_id == other.id),
                and_(Relationship.attacker_a_id == other.id, Relationship.attacker_b_id == attacker.id),
            )
        )
        res = await db.execute(stmt)
        existing_types = {r.rel_type for r in res.scalars().all()}

        candidates = []

        # 1. Same behavioral fingerprint
        if (
            attacker.fingerprint
            and other.fingerprint
            and attacker.fingerprint == other.fingerprint
            and "same_fingerprint" not in existing_types
        ):
            candidates.append({
                "rel_type": "same_fingerprint",
                "weight": 1.0,
                "evidence": [
                    f"Identical behavioral fingerprint hash: {attacker.fingerprint[:16]}...",
                    "Command sequence order and credential profile are matched",
                ],
            })

        # 2. Shared passwords or usernames (Jaccard >= 0.5)
        if "shared_credentials" not in existing_types:
            pass_sim = jaccard_similarity(set(attacker.passwords or []), set(other.passwords or []))
            user_sim = jaccard_similarity(set(attacker.usernames or []), set(other.usernames or []))
            if pass_sim >= JACCARD_THRESHOLD or user_sim >= JACCARD_THRESHOLD:
                ev = []
                if pass_sim >= JACCARD_THRESHOLD:
                    ev.append(f"Shared passwords Jaccard similarity: {pass_sim:.2f}")
                if user_sim >= JACCARD_THRESHOLD:
                    ev.append(f"Shared usernames Jaccard similarity: {user_sim:.2f}")
                candidates.append({
                    "rel_type": "shared_credentials",
                    "weight": round(max(pass_sim, user_sim), 2),
                    "evidence": ev,
                })

        # 3. Same malware URL or file hash
        if "shared_malware" not in existing_types:
            shared_urls = set(attacker.urls or []) & set(other.urls or [])
            shared_hashes = set(attacker.hashes or []) & set(other.hashes or [])
            if shared_urls or shared_hashes:
                ev = []
                if shared_urls:
                    ev.append(f"Shared payload URL: {list(shared_urls)[0]}")
                if shared_hashes:
                    ev.append(f"Shared malware file hash: {list(shared_hashes)[0]}")
                candidates.append({
                    "rel_type": "shared_malware",
                    "weight": 1.0,
                    "evidence": ev,
                })

        # 4. Same honeypot within 10 min window
        if "same_honeypot_window" not in existing_types:
            events_a = [e for e in recent_events if e.attacker_id == attacker.id]
            events_b = [e for e in recent_events if e.attacker_id == other.id]
            matched = False
            ev = []

            for ea in events_a:
                for eb in events_b:
                    if ea.honeypot == eb.honeypot:
                        ta = ea.timestamp if ea.timestamp.tzinfo else ea.timestamp.replace(tzinfo=timezone.utc)
                        tb = eb.timestamp if eb.timestamp.tzinfo else eb.timestamp.replace(tzinfo=timezone.utc)
                        delta = abs((ta - tb).total_seconds())
                        if delta <= SAME_WINDOW_SECONDS:
                            matched = True
                            ev.append(f"Simultaneous activity on {ea.honeypot} within {delta:.0f}s")
                            break
                if matched:
                    break

            if matched:
                candidates.append({
                    "rel_type": "same_honeypot_window",
                    "weight": 0.75,
                    "evidence": ev[:2],
                })

        for c in candidates:
            rel = Relationship(
                attacker_a_id=attacker.id,
                attacker_b_id=other.id,
                rel_type=c["rel_type"],
                weight=c["weight"],
                evidence=c["evidence"],
            )
            db.add(rel)
            new_edges.append({
                "attacker_a_id": attacker.id,
                "attacker_b_id": other.id,
                "attacker_a_ip": attacker.ip,
                "attacker_b_ip": other.ip,
                "rel_type": c["rel_type"],
                "weight": c["weight"],
                "evidence": c["evidence"],
            })

    if new_edges:
        await db.flush()

    return new_edges
