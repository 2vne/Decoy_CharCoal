from __future__ import annotations
from datetime import datetime, timezone, timedelta
from typing import Optional
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import Event

BRUTE_FORCE_WINDOW = 120  # 2 minutes
BRUTE_FORCE_COUNT = 5


async def classify_event(
    db: AsyncSession,
    event_type: str,
    src_ip: str,
    decoy_type: str,
    command: Optional[str],
    honeypot: str,
    attacker_id: Optional[int],
) -> Optional[str]:
    # 1. Internal decoy touched is always lateral_movement
    if decoy_type == "internal":
        return "lateral_movement"

    # 2. Port scan
    if event_type == "scan":
        return "port_scan"

    # 3. Suspicious login
    if event_type == "login_success":
        return "suspicious_login"

    # 4. Brute force check (>= 5 login_failed in 2 min)
    if event_type == "login_failed":
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(seconds=BRUTE_FORCE_WINDOW)
        stmt = select(func.count(Event.id)).where(
            Event.src_ip == src_ip,
            Event.event_type == "login_failed",
            Event.received_at >= start_time,
        )
        res = await db.execute(stmt)
        count = res.scalar_one() or 0
        if count >= BRUTE_FORCE_COUNT - 1:  # including current event
            return "brute_force"
        return None

    # 5. File upload/download or exploit
    if event_type in ("file_download", "file_upload", "exploit"):
        return "malware_attempt"

    # 6. Command examination
    if event_type == "command" and command:
        cmd_lower = command.lower()

        # Persistence attempt
        if any(k in cmd_lower for k in ["crontab", "rc.local", "systemctl enable", "/etc/cron", "init.d"]):
            return "persistence_attempt"

        # Malware attempt
        if any(k in cmd_lower for k in ["wget", "curl", "tftp", "chmod +x", "python -c", "bash -i", "/dev/tcp"]):
            return "malware_attempt"

        # Recon
        if any(k in cmd_lower for k in ["whoami", "id", "uname", "cat /etc/passwd", "ls", "find", " w ", "last", "ifconfig", "ip addr", "netstat"]):
            return "recon"

    return None

