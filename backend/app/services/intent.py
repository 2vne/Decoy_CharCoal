from __future__ import annotations
from typing import List, Tuple

INTENTS = [
    "credential_theft",
    "file_discovery",
    "malware_deployment",
    "persistence",
    "reconnaissance",
    "lateral_movement",
]


def classify_intent(
    event_types: List[str],
    commands: List[str],
    decoy_types: List[str],
    classifications: List[str],
) -> Tuple[str, List[str]]:
    scores = {i: 0 for i in INTENTS}
    evidence = {i: [] for i in INTENTS}

    all_cmds = " ".join(commands).lower()

    # Lateral movement: internal decoy touched
    if "internal" in decoy_types or "lateral_movement" in classifications:
        scores["lateral_movement"] += 50
        evidence["lateral_movement"].append("Internal decoy system accessed")

    # Malware deployment
    if any(k in all_cmds for k in ["wget", "curl", "tftp", "chmod +x", "python -c"]):
        scores["malware_deployment"] += 35
        evidence["malware_deployment"].append("Malware download or payload execution commands")
    if "file_download" in event_types or "file_upload" in event_types or "malware_attempt" in classifications:
        scores["malware_deployment"] += 25
        evidence["malware_deployment"].append("Payload staging or file transfer activity")

    # Persistence
    if any(k in all_cmds for k in ["crontab", "rc.local", "systemctl enable", "/etc/cron", "init.d"]):
        scores["persistence"] += 30
        evidence["persistence"].append("Persistence configuration commands executed")

    # Credential theft
    if "login_failed" in event_types or "brute_force" in classifications:
        scores["credential_theft"] += 25
        evidence["credential_theft"].append("Multiple authentication failures / brute force pattern")
    if "login_success" in event_types or "suspicious_login" in classifications:
        scores["credential_theft"] += 20
        evidence["credential_theft"].append("Successful authentication to honeypot")

    # File discovery
    if any(k in all_cmds for k in ["ls", "find", "dir", "cat /etc/passwd"]):
        scores["file_discovery"] += 20
        evidence["file_discovery"].append("Directory and sensitive file enumeration")

    # Reconnaissance
    if "scan" in event_types or "port_scan" in classifications:
        scores["reconnaissance"] += 15
        evidence["reconnaissance"].append("Network port sweep / probe detected")
    if any(k in all_cmds for k in ["whoami", "id", "uname", "ifconfig", "netstat", "ip addr", "w", "last"]):
        scores["reconnaissance"] += 15
        evidence["reconnaissance"].append("Host identity & network enumeration commands")

    top_intent = max(scores, key=lambda k: scores[k])
    if scores[top_intent] == 0:
        top_intent = "reconnaissance"
        evidence[top_intent] = ["Baseline traffic observation"]

    return top_intent, evidence[top_intent]

