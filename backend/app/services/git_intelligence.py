from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
import subprocess
from typing import Any, Dict, List, Optional
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import CommitAttribution, GatewayIncident
from app.services.notifications import send_resend_email

REPO_ROOT = Path(__file__).resolve().parents[3]

# Path to Team mapping heuristics
TEAM_PATH_MAP = [
    ("payment", "Payments"),
    ("checkout", "Payments"),
    ("billing", "Payments"),
    ("frontend", "Frontend / UI"),
    ("models.py", "Database"),
    ("db.py", "Database"),
    ("nginx", "DevOps / Infrastructure"),
    ("collector", "DevOps / Infrastructure"),
    ("docker", "DevOps / Infrastructure"),
    ("risk", "Security"),
    ("enforcer", "Security"),
    ("mitre", "Security"),
    ("backend", "Backend"),
]


def resolve_team_from_paths(changed_files: List[str]) -> str:
    """Resolves responsible team based on changed file paths."""
    for file_path in changed_files:
        lower_path = file_path.lower()
        for keyword, team in TEAM_PATH_MAP:
            if keyword in lower_path:
                return team
    return "Backend"


def get_local_git_commits(max_count: int = 15) -> List[Dict[str, Any]]:
    """
    Safely reads actual local Git history from the repository.
    Never fabricates commits, hashes, or author identities.
    """
    commits = []
    try:
        # Format: %H|%an|%ae|%aI|%s
        cmd = ["git", "log", f"-n{max_count}", "--pretty=format:%H|%an|%ae|%aI|%s", "--name-only"]
        res = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=True)
        raw_output = res.stdout.strip()
        if not raw_output:
            return []

        # Parse git log blocks
        blocks = raw_output.split("\n\n")
        for block in blocks:
            lines = [l.strip() for l in block.splitlines() if l.strip()]
            if not lines:
                continue
            header = lines[0]
            parts = header.split("|")
            if len(parts) >= 5:
                commit_hash, author, email, iso_date, subject = parts[0], parts[1], parts[2], parts[3], parts[4]
                changed_files = lines[1:] if len(lines) > 1 else []
                try:
                    dt = datetime.fromisoformat(iso_date)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                except Exception:
                    dt = datetime.now(timezone.utc)

                commits.append({
                    "commit_hash": commit_hash,
                    "author_name": author,
                    "author_email": email,
                    "commit_ts": dt,
                    "commit_msg": subject,
                    "changed_files": changed_files,
                })
    except Exception as e:
        # Fallback if git is not accessible
        pass

    return commits


async def correlate_commits_for_incident(
    db: AsyncSession,
    incident_id: int,
    affected_function: str = "",
    affected_endpoint: str = "",
    incident_start_ts: Optional[datetime] = None,
) -> List[CommitAttribution]:
    """
    Correlates actual Git commits with the incident window and affected paths.
    Strictly applies non-accusatory language and objective evidence criteria.
    """
    now = incident_start_ts or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    commits = get_local_git_commits(max_count=20)
    attributions = []

    for c in commits:
        c_ts = c["commit_ts"]
        # Calculate time delta in minutes
        delta_seconds = (now - c_ts).total_seconds()
        delta_minutes = round(delta_seconds / 60, 1)

        # Check if commit touched files relevant to the incident endpoint or function
        relevant = False
        relevance_reason = ""
        for f in c["changed_files"]:
            f_lower = f.lower()
            if affected_function and affected_function.replace("auth_", "") in f_lower:
                relevant = True
                relevance_reason = f"touched function file {f}"
                break
            if affected_endpoint and any(seg in f_lower for seg in affected_endpoint.split("/") if len(seg) > 3):
                relevant = True
                relevance_reason = f"touched endpoint file {f}"
                break

        # Also consider commits in recent proximity (e.g. within 2 hours before incident)
        if not relevant and 0 <= delta_minutes <= 120.0:
            relevant = True
            relevance_reason = "authored shortly before incident detection"

        if relevant:
            assigned_team = resolve_team_from_paths(c["changed_files"])
            short_hash = c["commit_hash"][:8]

            if delta_minutes >= 0:
                time_desc = f"{delta_minutes:.0f} minutes before"
            else:
                time_desc = f"{abs(delta_minutes):.0f} minutes after"

            explanation = (
                f"Commit {short_hash} by {c['author_name']} ({relevance_reason}) was recorded {time_desc} "
                f"the incident detection time. This represents a potential investigation lead for the "
                f"{assigned_team.upper()} team, not proof of fault."
            )

            confidence = 0.85 if relevance_reason.startswith("touched") else 0.65

            attr = CommitAttribution(
                incident_id=incident_id,
                commit_hash=c["commit_hash"],
                author_name=c["author_name"],
                author_email=c["author_email"],
                commit_msg=c["commit_msg"],
                commit_ts=c_ts,
                changed_files=c["changed_files"],
                related_function=affected_function,
                assigned_team=assigned_team,
                confidence=confidence,
                correlation_explanation=explanation,
            )
            db.add(attr)
            attributions.append(attr)

    await db.flush()
    return attributions

