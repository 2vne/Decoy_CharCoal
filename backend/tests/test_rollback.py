from __future__ import annotations
from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy import select
from app.models import Block
from app.services.enforcer import _is_safe, request_block, rollback_expired_blocks


class TestSafeIPProtection:
    def test_rfc1918_is_safe(self):
        assert _is_safe("10.0.0.1") is True
        assert _is_safe("172.16.0.1") is True
        assert _is_safe("192.168.1.1") is True
        assert _is_safe("127.0.0.1") is True

    def test_public_ip_not_safe(self):
        assert _is_safe("8.8.8.8") is False
        assert _is_safe("45.33.32.156") is False


@pytest.mark.asyncio
class TestBlockRollback:
    async def test_expired_block_rolled_back(self, db):
        now = datetime.now(timezone.utc)
        expired_time = now - timedelta(seconds=20)

        async with db.begin():
            b = Block(
                ip="198.51.100.99",
                requested_by="test",
                ttl_seconds=10,
                status="active",
                requested_at=expired_time,
                expires_at=expired_time + timedelta(seconds=10),
                mock=True,
            )
            db.add(b)
            await db.flush()

        async with db.begin():
            rolled = await rollback_expired_blocks(db)

        assert rolled >= 1

        stmt = select(Block).where(Block.ip == "198.51.100.99")
        updated = (await db.execute(stmt)).scalar_one()
        assert updated.status == "rolled_back"
        assert updated.rolled_back_at is not None

    async def test_request_block_refuses_safe_ip(self, db):
        async with db.begin():
            res = await request_block(db, "192.168.1.50", None)
        assert res is None

