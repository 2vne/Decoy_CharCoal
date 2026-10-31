from __future__ import annotations
import csv
from datetime import datetime, timezone
import io
import json
from typing import Any, Dict, List
import uuid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import Attacker, Event


async def extract_iocs(db: AsyncSession) -> List[Dict[str, Any]]:
    iocs: List[Dict[str, Any]] = []
    seen = set()

    # 1. Attacker IPs
    stmt_atks = select(Attacker).where(Attacker.risk_score >= 30)
    res_atks = await db.execute(stmt_atks)
    for atk in res_atks.scalars().all():
        if atk.ip not in seen:
            seen.add(atk.ip)
            iocs.append({
                "type": "ipv4-addr",
                "value": atk.ip,
                "attacker_id": atk.id,
                "ip": atk.ip,
                "confidence": min(100, int(atk.risk_score)),
                "honeypots": list(atk.honeypots_touched or []),
                "first_seen": atk.first_seen.isoformat() if atk.first_seen else "",
                "last_seen": atk.last_seen.isoformat() if atk.last_seen else "",
                "description": f"Hostile actor targeting {', '.join(atk.honeypots_touched or [])} with risk {atk.risk_score:.0f}",
            })

        # URLs
        for u in (atk.urls or []):
            if u not in seen:
                seen.add(u)
                iocs.append({
                    "type": "url",
                    "value": u,
                    "attacker_id": atk.id,
                    "ip": atk.ip,
                    "confidence": 90,
                    "honeypots": list(atk.honeypots_touched or []),
                    "first_seen": atk.first_seen.isoformat() if atk.first_seen else "",
                    "last_seen": atk.last_seen.isoformat() if atk.last_seen else "",
                    "description": f"Malware payload / C2 URL dropped by {atk.ip}",
                })

        # Hashes
        for h in (atk.hashes or []):
            if h not in seen:
                seen.add(h)
                iocs.append({
                    "type": "file-hash",
                    "value": h,
                    "attacker_id": atk.id,
                    "ip": atk.ip,
                    "confidence": 95,
                    "honeypots": list(atk.honeypots_touched or []),
                    "first_seen": atk.first_seen.isoformat() if atk.first_seen else "",
                    "last_seen": atk.last_seen.isoformat() if atk.last_seen else "",
                    "description": f"Malicious sample hash observed in deception environment from {atk.ip}",
                })

    return iocs


def format_iocs_csv(iocs: List[Dict[str, Any]]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["type", "value", "source_ip", "confidence", "honeypots", "first_seen", "description"])
    for item in iocs:
        writer.writerow([
            item["type"],
            item["value"],
            item["ip"],
            item["confidence"],
            ";".join(item["honeypots"]),
            item["first_seen"],
            item["description"],
        ])
    return output.getvalue()


def format_iocs_stix(iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    stix_objects = []

    for item in iocs:
        indicator_id = f"indicator--{uuid.uuid4()}"
        pattern = ""
        if item["type"] == "ipv4-addr":
            pattern = f"[ipv4-addr:value = '{item['value']}']"
        elif item["type"] == "url":
            pattern = f"[url:value = '{item['value']}']"
        elif item["type"] == "file-hash":
            pattern = f"[file:hashes.'SHA-256' = '{item['value']}']"
        else:
            pattern = f"[artifact:payload_bin = '{item['value']}']"

        stix_objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"Sentinel SOC Deception Indicator: {item['value']}",
            "description": item["description"],
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": item["first_seen"] or now_iso,
            "confidence": item["confidence"],
        })

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": stix_objects,
    }

