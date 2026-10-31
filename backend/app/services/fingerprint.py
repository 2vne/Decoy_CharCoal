from __future__ import annotations
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import statistics
from typing import Any, Dict, List, Tuple


def compute_fingerprint(
    commands: List[str],
    usernames: List[str],
    passwords: List[str],
    event_timestamps: List[datetime],
) -> Tuple[str, Dict[str, Any]]:
    # First 5 distinct commands in order of appearance
    seen_cmds = []
    for cmd in commands:
        if cmd and cmd not in seen_cmds:
            seen_cmds.append(cmd)
        if len(seen_cmds) >= 5:
            break

    # Top sorted usernames and passwords
    def get_top_sorted(items: List[str], limit: int = 3) -> List[str]:
        cleaned = [x for x in items if x]
        if not cleaned:
            return []
        counts = Counter(cleaned)
        most_common = [k for k, _ in counts.most_common(limit)]
        return sorted(most_common)

    top_users = get_top_sorted(usernames, 3)
    top_passes = get_top_sorted(passwords, 3)

    # Median gap between consecutive events in seconds
    gaps: List[float] = []
    clean_ts = []
    for ts in event_timestamps:
        if ts is not None:
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            clean_ts.append(ts)

    if len(clean_ts) >= 2:
        sorted_ts = sorted(clean_ts)
        for i in range(1, len(sorted_ts)):
            t1 = sorted_ts[i - 1]
            t2 = sorted_ts[i]
            delta = abs((t2 - t1).total_seconds())
            gaps.append(delta)

    median_gap = float(statistics.median(gaps)) if gaps else 0.0

    # Build canonical payload for hashing
    payload = {
        "commands": seen_cmds,
        "usernames": top_users,
        "passwords": top_passes,
    }
    raw_str = json.dumps(payload, sort_keys=True)
    fingerprint = hashlib.sha256(raw_str.encode("utf-8")).hexdigest()

    all_cmds_str = " ".join(commands).lower()
    feature_vector = {
        "num_commands": len(commands),
        "num_distinct_commands": len(set(commands)),
        "num_usernames": len(usernames),
        "num_passwords": len(passwords),
        "num_distinct_usernames": len(set(usernames)),
        "num_distinct_passwords": len(set(passwords)),
        "median_gap_seconds": round(median_gap, 2),
        "total_events": len(event_timestamps),
        "has_download": 1.0 if any(k in all_cmds_str for k in ["wget", "curl", "tftp", "fetch"]) else 0.0,
        "has_persistence": 1.0 if any(k in all_cmds_str for k in ["crontab", "rc.local", "systemctl", "init.d"]) else 0.0,
    }

    return fingerprint, feature_vector
