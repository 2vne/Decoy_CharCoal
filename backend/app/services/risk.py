from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple

BANDS = [
    (0, 25, "low"),
    (26, 50, "medium"),
    (51, 75, "high"),
    (76, 100, "critical"),
]


def score_to_band(score: float) -> str:
    for lo, hi, band in BANDS:
        if lo <= score <= hi:
            return band
    return "critical"


def compute_risk(
    event_types: List[str],
    classifications: List[Optional[str]],
    honeypots_touched: List[str],
    decoy_types: List[str],
    is_repeat: bool,
    is_anomaly: bool,
    related_high_risk: bool = False,
    external_reputation: float = 0.0,
) -> Tuple[float, List[Dict[str, Any]], str]:
    factors: List[Dict[str, Any]] = []

    def add(factor: str, points: int, reason: str):
        factors.append({"factor": factor, "points": points, "reason": reason})

    clean_class = [c for c in classifications if c]

    # scan only +10
    if "scan" in event_types or "port_scan" in clean_class:
        add("scan", 10, "Port scanning activity observed")

    # brute_force +20
    if "brute_force" in clean_class:
        add("brute_force", 20, "Brute force login attempts detected")

    # login_success +20
    if "login_success" in event_types or "suspicious_login" in clean_class:
        add("login_success", 20, "Successful login on honeypot — high confidence compromise")

    # recon +10
    if "recon" in clean_class:
        add("recon", 10, "Reconnaissance commands executed")

    # download/upload +20
    if any(e in event_types for e in ("file_download", "file_upload")) or "malware_attempt" in clean_class:
        add("download_upload", 20, "File transfer activity — potential malware staging")

    # persistence +15
    if "persistence_attempt" in clean_class:
        add("persistence", 15, "Persistence mechanism attempt detected")

    # 2+ honeypots +15
    if len(set(honeypots_touched)) >= 2:
        add("multi_honeypot", 15, f"Attacker touched {len(set(honeypots_touched))} honeypots")

    # internal decoy +25
    if "internal" in decoy_types or "lateral_movement" in clean_class:
        add("internal_decoy", 25, "Internal decoy accessed — lateral movement indicator")

    # repeat +10
    if is_repeat:
        add("repeat_attacker", 10, "Known repeat attacker (same fingerprint as previous profile)")

    # related to another high-risk attacker +10
    if related_high_risk:
        add("related_high_risk", 10, "Correlated with another high-risk profile via relationship graph")

    # external reputation>50 +10
    if external_reputation > 50:
        add("external_reputation", 10, f"External reputation score {external_reputation:.0f} > 50")

    # anomaly +10
    if is_anomaly:
        add("anomaly", 10, "Isolation Forest anomaly detection flagged this attacker profile")

    raw_points = sum(f["points"] for f in factors)
    score = min(100.0, float(raw_points))
    band = score_to_band(score)

    return score, factors, band

