from __future__ import annotations
import pytest
from app.services.dedup import get_or_create_alert


@pytest.mark.asyncio
class TestDedup:
    async def test_first_event_creates_alert(self, db):
        async with db.begin():
            alert, is_new = await get_or_create_alert(
                db=db,
                src_ip="1.2.3.4",
                event_type="scan",
                honeypot="cowrie",
                event_uuid="uuid-001",
                attacker_id=None,
            )
        assert is_new is True
        assert alert.count == 1
        assert alert.src_ip == "1.2.3.4"

    async def test_duplicate_collapses(self, db):
        async with db.begin():
            alert1, is_new1 = await get_or_create_alert(
                db=db,
                src_ip="1.2.3.5",
                event_type="login_failed",
                honeypot="cowrie",
                event_uuid="uuid-002",
                attacker_id=None,
            )
        async with db.begin():
            alert2, is_new2 = await get_or_create_alert(
                db=db,
                src_ip="1.2.3.5",
                event_type="login_failed",
                honeypot="cowrie",
                event_uuid="uuid-003",
                attacker_id=None,
            )
        assert is_new1 is True
        assert is_new2 is False
        assert alert2.count == 2
        assert alert2.alerts_suppressed == 1

    async def test_different_ip_creates_new_alert(self, db):
        async with db.begin():
            alert1, _ = await get_or_create_alert(
                db=db,
                src_ip="1.2.3.6",
                event_type="scan",
                honeypot="cowrie",
                event_uuid="uuid-004",
                attacker_id=None,
            )
        async with db.begin():
            alert2, is_new = await get_or_create_alert(
                db=db,
                src_ip="1.2.3.7",
                event_type="scan",
                honeypot="cowrie",
                event_uuid="uuid-005",
                attacker_id=None,
            )
        assert is_new is True

    async def test_different_event_type_creates_new_alert(self, db):
        async with db.begin():
            alert1, _ = await get_or_create_alert(
                db=db,
                src_ip="1.2.3.8",
                event_type="scan",
                honeypot="cowrie",
                event_uuid="uuid-006",
                attacker_id=None,
            )
        async with db.begin():
            alert2, is_new = await get_or_create_alert(
                db=db,
                src_ip="1.2.3.8",
                event_type="login_failed",
                honeypot="cowrie",
                event_uuid="uuid-007",
                attacker_id=None,
            )
        assert is_new is True

