from __future__ import annotations
from dataclasses import dataclass, field
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger("sentinel.playbooks")

PLAYBOOKS_FILE = Path(__file__).resolve().parent.parent / "config" / "playbooks.yaml"


class PlaybookAction(BaseModel):
    step: str
    why: str = ""


class StagedReopenPhase(BaseModel):
    phase: int
    traffic_percent: int
    exit_criteria: str


class PlaybookTrigger(BaseModel):
    categories: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    classifications: List[str] = Field(default_factory=list)
    intent: List[str] = Field(default_factory=list)


class PlaybookModel(BaseModel):
    id: str
    title: str
    severity: str = "medium"
    trigger: PlaybookTrigger = Field(default_factory=PlaybookTrigger)
    immediate_actions: List[PlaybookAction] = Field(default_factory=list)
    before_reopening: List[PlaybookAction] = Field(default_factory=list)
    staged_reopen: List[StagedReopenPhase] = Field(default_factory=list)
    monitoring_after_restore: List[PlaybookAction] = Field(default_factory=list)
    long_term_fixes: List[PlaybookAction] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def id_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Playbook id must not be empty")
        return v.strip()


_PLAYBOOK_CACHE: Optional[Dict[str, PlaybookModel]] = None


def load_playbooks(file_path: Optional[Path] = None, reload: bool = False) -> Dict[str, PlaybookModel]:
    """
    Loads and validates playbooks from YAML file using Pydantic schema validation.
    Cached after first load unless reload=True.
    """
    global _PLAYBOOK_CACHE
    if _PLAYBOOK_CACHE is not None and not reload:
        return _PLAYBOOK_CACHE

    target_path = file_path or PLAYBOOKS_FILE
    if not target_path.exists():
        raise FileNotFoundError(f"Playbooks file not found at {target_path}")

    with open(target_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict) or "playbooks" not in data:
        raise ValueError("Invalid playbooks.yaml structure: expected top-level 'playbooks' key")

    playbooks: Dict[str, PlaybookModel] = {}
    for entry in data["playbooks"]:
        validated = PlaybookModel.model_validate(entry)
        if validated.id in playbooks:
            raise ValueError(f"Duplicate playbook id detected: {validated.id}")
        playbooks[validated.id] = validated

    _PLAYBOOK_CACHE = playbooks
    logger.info(f"Loaded and validated {len(playbooks)} security playbooks from {target_path.name}")
    return _PLAYBOOK_CACHE


def get_playbook(playbook_id: str) -> Optional[PlaybookModel]:
    """Retrieves a single playbook by its ID."""
    playbooks = load_playbooks()
    return playbooks.get(playbook_id)


def get_all_playbooks() -> Dict[str, PlaybookModel]:
    """Returns all validated security playbooks indexed by id."""
    return load_playbooks()



def match_playbooks(
    categories: Optional[List[str]] = None,
    mitre_techniques: Optional[List[str]] = None,
    classification: Optional[str] = None,
    intent: Optional[str] = None,
    is_reattack: bool = False,
) -> List[PlaybookModel]:
    """
    Matches relevant playbooks by trigger rules:
    - categories: checks for exact match or substring match against playbook triggers
    - mitre_techniques: checks technique ID (e.g. T1110, T1053)
    - classification: checks severity classification
    - intent: checks intent keyword
    - is_reattack: automatically injects pb_reattack_after_restore
    """
    playbooks = load_playbooks()
    matched_ids: set[str] = set()

    clean_cats = [c.lower().strip() for c in (categories or []) if c]
    clean_techniques = [t.upper().strip() for t in (mitre_techniques or []) if t]
    clean_class = (classification or "").upper().strip()
    clean_intent = (intent or "").lower().strip()

    if is_reattack and "pb_reattack_after_restore" in playbooks:
        matched_ids.add("pb_reattack_after_restore")

    for pb_id, pb in playbooks.items():
        if pb_id == "pb_reattack_after_restore" and not is_reattack:
            continue

        trigger = pb.trigger

        # 1. Match categories
        trigger_cats = [c.lower() for c in trigger.categories]
        for cat in clean_cats:
            if cat in trigger_cats or any(c in cat for c in trigger_cats) or any(cat in c for c in trigger_cats):
                matched_ids.add(pb_id)
                break

        # 2. Match MITRE techniques
        trigger_techs = [t.upper() for t in trigger.mitre_techniques]
        for tech in clean_techniques:
            if tech in trigger_techs or any(t.startswith(tech) or tech.startswith(t) for t in trigger_techs):
                matched_ids.add(pb_id)
                break

        # 3. Match classification
        if clean_class and clean_class in [c.upper() for c in trigger.classifications]:
            # Classification alone is a loose match; only match if at least one category or intent aligned or high
            if pb_id in matched_ids:
                pass

        # 4. Match intent
        if clean_intent and any(clean_intent in i.lower() or i.lower() in clean_intent for i in trigger.intent):
            matched_ids.add(pb_id)

    # Sort matched playbooks by severity (critical > high > medium > low), prioritizing reattack playbook
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    matched_list = [playbooks[pid] for pid in matched_ids if pid in playbooks]
    matched_list.sort(
        key=lambda p: (5 if (p.id == "pb_reattack_after_restore" and is_reattack) else severity_rank.get(p.severity.lower(), 1)),
        reverse=True,
    )

    # Fallback to general API abuse if nothing matched
    if not matched_list and "pb_api_abuse" in playbooks:
        matched_list.append(playbooks["pb_api_abuse"])

    return matched_list
