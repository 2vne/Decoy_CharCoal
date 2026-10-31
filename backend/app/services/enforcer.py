from __future__ import annotations
import asyncio
from datetime import datetime, timezone, timedelta
import ipaddress
import logging
from typing import Any, Dict, List, Optional
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.models import Attacker, Block, ResponseAction
from app.services.broadcast import broadcast

logger = logging.getLogger(__name__)

RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_safe(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        if any(addr in net for net in RFC1918_NETWORKS):
            return True
    except ValueError:
        pass

    safe_list = settings.safe_ips
    if isinstance(safe_list, str):
        safe_list = [s.strip() for s in safe_list.split(",") if s.strip()]
    return ip in safe_list


async def request_block(
    db: AsyncSession,
    ip: str,
    attacker_id: Optional[int],
    ttl_seconds: int = 600,
    requested_by: str = "system",
) -> Optional[Block]:
    if _is_safe(ip):
        logger.warning(f"Refusing to block safe or RFC1918 address: {ip}")
        return None

    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=ttl_seconds)

    block = Block(
        ip=ip,
        attacker_id=attacker_id,
        requested_by=requested_by,
        ttl_seconds=ttl_seconds,
        status="pending",
        requested_at=now,
        expires_at=expires,
        mock=settings.mock_mode or not bool(settings.enforcer_url),
    )
    db.add(block)
    await db.flush()

    if block.mock:
        # In mock mode, immediately mark active and verified
        block.status = "active"
        block.verified_at = now
        await db.flush()
    else:
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                res = await client.post(
                    f"{settings.enforcer_url.rstrip('/')}/block",
                    json={"ip": ip, "ttl_seconds": ttl_seconds},
                    headers={"Authorization": f"Bearer {settings.enforcer_token}"},
                )
                if res.status_code in (200, 201):
                    block.status = "active"
                    block.verified_at = datetime.now(timezone.utc)
                else:
                    block.status = "failed"
                await db.flush()
        except Exception as e:
            logger.error(f"External enforcer call failed for {ip}: {e}")
            block.status = "failed"
            await db.flush()

    # Update attacker status if attacker_id is known
    if attacker_id:
        stmt = select(Attacker).where(Attacker.id == attacker_id)
        res = await db.execute(stmt)
        attacker = res.scalar_one_or_none()
        if attacker:
            attacker.status = "blocked"
            await db.flush()

    try:
        await broadcast("block", {
            "block_id": block.id,
            "ip": block.ip,
            "status": block.status,
            "ttl_seconds": block.ttl_seconds,
            "expires_at": block.expires_at.isoformat() if block.expires_at else None,
            "verified_at": block.verified_at.isoformat() if block.verified_at else None,
        })
    except Exception:
        pass

    return block


async def request_unblock(db: AsyncSession, ip: str) -> bool:
    stmt = select(Block).where(Block.ip == ip, Block.status.in_(["active", "pending"]))
    res = await db.execute(stmt)
    active_blocks = res.scalars().all()

    if not active_blocks:
        return False

    now = datetime.now(timezone.utc)
    for b in active_blocks:
        if not b.mock and settings.enforcer_url:
            try:
                async with httpx.AsyncClient(timeout=4.0) as client:
                    await client.post(
                        f"{settings.enforcer_url.rstrip('/')}/unblock",
                        json={"ip": ip},
                        headers={"Authorization": f"Bearer {settings.enforcer_token}"},
                    )
            except Exception as e:
                logger.error(f"External unblock failed for {ip}: {e}")

        b.status = "rolled_back"
        b.rolled_back_at = now

    # Also update ResponseAction records
    stmt_act = select(ResponseAction).where(
        ResponseAction.target_ip == ip,
        ResponseAction.status.in_(["executed", "verified", "approved"]),
    )
    act_res = await db.execute(stmt_act)
    for act in act_res.scalars().all():
        act.status = "rolled_back"
        act.rolled_back_at = now

    stmt_atk = select(Attacker).where(Attacker.ip == ip)
    atk_res = await db.execute(stmt_atk)
    atk = atk_res.scalar_one_or_none()
    if atk and atk.status == "blocked":
        atk.status = "active"

    await db.flush()

    try:
        await broadcast("rollback", {
            "ip": ip,
            "rolled_back_at": now.isoformat(),
        })
    except Exception:
        pass

    return True


async def verify_block(ip: str) -> bool:
    if settings.mock_mode or not settings.enforcer_url:
        return True

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(
                f"{settings.enforcer_url.rstrip('/')}/verify/{ip}",
                headers={"Authorization": f"Bearer {settings.enforcer_token}"},
            )
            return r.status_code == 200 and r.json().get("blocked", False)
    except Exception:
        return False


async def get_enforcer_blocks() -> List[Dict[str, Any]]:
    if settings.mock_mode or not settings.enforcer_url:
        return []

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(
                f"{settings.enforcer_url.rstrip('/')}/blocks",
                headers={"Authorization": f"Bearer {settings.enforcer_token}"},
            )
            if r.status_code == 200:
                return r.json()
    except Exception:
        pass
    return []


async def rollback_expired_blocks(db: AsyncSession) -> int:
    now = datetime.now(timezone.utc)
    stmt = select(Block).where(Block.status == "active", Block.expires_at <= now)
    res = await db.execute(stmt)
    expired = res.scalars().all()

    count = 0
    for b in expired:
        await request_unblock(db, b.ip)
        count += 1

    return count

