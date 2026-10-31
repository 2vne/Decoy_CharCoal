from __future__ import annotations
from datetime import datetime, timezone
import pytest
from app.models import Attacker
from app.services.correlate import find_and_store_relationships, jaccard_similarity, JACCARD_THRESHOLD


class TestJaccardSimilarity:
    def test_identical_sets_is_1(self):
        assert jaccard_similarity({"a", "b", "c"}, {"a", "b", "c"}) == 1.0

    def test_disjoint_sets_is_0(self):
        assert jaccard_similarity({"a", "b"}, {"c", "d"}) == 0.0

    def test_partial_overlap(self):
        result = jaccard_similarity({"a", "b", "c"}, {"b", "c", "d"})
        assert abs(result - 0.5) < 0.001

    def test_threshold_met(self):
        result = jaccard_similarity({"a", "b"}, {"a", "b", "c", "d"})
        assert result >= JACCARD_THRESHOLD


@pytest.mark.asyncio
class TestRelationshipDetection:
    async def test_same_fingerprint_creates_relationship(self, db):
        now = datetime.now(timezone.utc)
        fp = "hash1234567890abcdef" * 3

        async with db.begin():
            a1 = Attacker(
                ip="198.51.100.1",
                first_seen=now, last_seen=now,
                fingerprint=fp,
                honeypots_touched=["cowrie"],
                passwords=["root"], usernames=["root"],
                urls=[], hashes=[], commands=[],
            )
            a2 = Attacker(
                ip="198.51.100.2",
                first_seen=now, last_seen=now,
                fingerprint=fp,
                honeypots_touched=["cowrie"],
                passwords=["root"], usernames=["root"],
                urls=[], hashes=[], commands=[],
            )
            db.add(a1)
            db.add(a2)
            await db.flush()

            new_rels = await find_and_store_relationships(
                db=db,
                attacker=a1,
                all_attackers=[a2],
                recent_events=[],
            )

        assert len(new_rels) >= 1
        assert any(r["rel_type"] == "same_fingerprint" for r in new_rels)

    async def test_shared_credentials_creates_relationship(self, db):
        now = datetime.now(timezone.utc)
        shared_passwords = ["p1", "p2", "p3", "p4", "p5"]

        async with db.begin():
            a1 = Attacker(
                ip="198.51.100.3",
                first_seen=now, last_seen=now,
                fingerprint="fp1",
                honeypots_touched=["cowrie"],
                passwords=shared_passwords, usernames=["admin"],
                urls=[], hashes=[], commands=[],
            )
            a2 = Attacker(
                ip="198.51.100.4",
                first_seen=now, last_seen=now,
                fingerprint="fp2",
                honeypots_touched=["cowrie"],
                passwords=shared_passwords, usernames=["admin"],
                urls=[], hashes=[], commands=[],
            )
            db.add(a1)
            db.add(a2)
            await db.flush()

            new_rels = await find_and_store_relationships(
                db=db,
                attacker=a1,
                all_attackers=[a2],
                recent_events=[],
            )

        assert any(r["rel_type"] == "shared_credentials" for r in new_rels)

