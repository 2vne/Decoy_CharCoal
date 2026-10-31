from __future__ import annotations
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class EventIn(BaseModel):
    model_config = ConfigDict(extra="allow")

    event_id: str
    timestamp: datetime
    honeypot: str
    decoy_type: str = "external"
    src_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    session_id: Optional[str] = None
    event_type: str = "other"
    username: Optional[str] = None
    password: Optional[str] = None
    command: Optional[str] = None
    url: Optional[str] = None
    file_hash: Optional[str] = None
    raw: Dict[str, Any] = Field(default_factory=dict)


class EventOut(BaseModel):
    id: int
    event_id: str
    timestamp: Optional[str] = None
    received_at: Optional[str] = None
    honeypot: str
    decoy_type: str
    src_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    session_id: Optional[str] = None
    event_type: str
    username: Optional[str] = None
    command: Optional[str] = None
    url: Optional[str] = None
    file_hash: Optional[str] = None
    attacker_id: Optional[int] = None
    normalised: Optional[Dict[str, Any]] = None
    raw: Dict[str, Any] = Field(default_factory=dict)


class AttackerOut(BaseModel):
    id: int
    ip: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    total_events: int = 0
    honeypots_touched: List[str] = Field(default_factory=list)
    ports: List[int] = Field(default_factory=list)
    usernames: List[str] = Field(default_factory=list)
    passwords: List[str] = Field(default_factory=list)
    commands: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    hashes: List[str] = Field(default_factory=list)
    sessions: List[str] = Field(default_factory=list)
    is_repeat: bool = False
    status: str = "active"
    fingerprint: Optional[str] = None
    feature_vector: Optional[Dict[str, Any]] = None
    risk_score: float = 0.0
    risk_band: str = "low"
    risk_factors: List[Dict[str, Any]] = Field(default_factory=list)
    risk_history: List[Dict[str, Any]] = Field(default_factory=list)
    intent: Optional[str] = None
    intent_evidence: List[str] = Field(default_factory=list)
    is_anomaly: bool = False
    anomaly_score: Optional[float] = None
    geo: Dict[str, Any] = Field(default_factory=dict)


class RelationshipOut(BaseModel):
    id: int
    attacker_a_id: int
    attacker_b_id: int
    attacker_a_ip: Optional[str] = None
    attacker_b_ip: Optional[str] = None
    rel_type: str
    weight: float
    evidence: List[str]
    created_at: Optional[str] = None


class BlockOut(BaseModel):
    id: int
    ip: str
    attacker_id: Optional[int] = None
    requested_by: str = "system"
    ttl_seconds: int = 600
    status: str = "pending"
    mock: bool = False
    requested_at: Optional[str] = None
    verified_at: Optional[str] = None
    expires_at: Optional[str] = None
    rolled_back_at: Optional[str] = None


class IncidentOut(BaseModel):
    id: int
    attacker_id: Optional[int] = None
    title: str
    status: str
    status_history: List[Dict[str, Any]] = Field(default_factory=list)
    assignee: Optional[str] = None
    notes: List[Dict[str, Any]] = Field(default_factory=list)
    root_cause: Dict[str, Any] = Field(default_factory=dict)
    blast_radius: Dict[str, Any] = Field(default_factory=dict)
    ttd_seconds: Optional[float] = None
    ttr_seconds: Optional[float] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    risk_score_at_creation: float = 0.0
    ai_investigation: Optional[Dict[str, Any]] = None


class AIInvestigationOut(BaseModel):
    incident_id: int
    what_happened: str
    why_dangerous: str
    evidence_list: List[Dict[str, Any]]
    confidence: float
    recommended_actions: List[str]
    cached_at: Optional[str] = None
    model_used: str = "template_fallback"


class ActionApproveIn(BaseModel):
    approver: str = "analyst"
    duration_seconds: Optional[int] = None


class ActionRejectIn(BaseModel):
    approver: str = "analyst"
    reason: Optional[str] = None


class ResponseActionOut(BaseModel):
    id: int
    attacker_id: Optional[int] = None
    incident_id: Optional[int] = None
    block_id: Optional[int] = None
    action_type: str
    target_ip: str
    status: str
    reason: str
    duration_seconds: int
    approver: Optional[str] = None
    created_at: Optional[str] = None
    approved_at: Optional[str] = None
    rejected_at: Optional[str] = None
    executed_at: Optional[str] = None
    verified_at: Optional[str] = None
    rolled_back_at: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class AuditLogOut(BaseModel):
    id: int
    entity_type: str
    entity_id: str
    action: str
    actor: str
    details: Dict[str, Any]
    timestamp: str


class WhatIfRequest(BaseModel):
    attacker_id: int
    action: str = "block"  # block, delay, none
    at_stage: str = "recon"  # recon, brute_force, privilege_escalation, malware_staging, lateral_movement


class WhatIfOut(BaseModel):
    attacker_id: int
    ip: str
    action_simulated: str
    at_stage: str
    actual_risk: float
    projected_risk: float
    risk_reduction_pct: float
    stages_avoided: List[str]
    estimated_impact: str
    counterfactual_comparison: List[Dict[str, Any]]


class PredictionOut(BaseModel):
    attacker_id: int
    ip: str
    current_stage: str
    observed_honeypots: List[str]
    likely_next_targets: List[Dict[str, Any]]


class ExposureAssetOut(BaseModel):
    id: int
    name: str
    asset_type: str
    honeypot_link: str
    criticality: str
    exposure_score: float
    threshold: float
    breached: bool
    last_evaluated: Optional[str] = None


class ExposureUpdateIn(BaseModel):
    assets: List[Dict[str, Any]]


class IncidentPatch(BaseModel):
    status: Optional[str] = None
    assignee: Optional[str] = None
    note: Optional[str] = None


class NoteIn(BaseModel):
    text: str
    author: str = "analyst"


class SimulateRequest(BaseModel):
    scenario: str = "full_chain"
    speed: float = 1.0


class OverviewOut(BaseModel):
    total_events: int
    total_attackers: int
    total_incidents: int
    active_blocks: int
    band_counts: Dict[str, int]
    events_today: int
    honeypots_healthy: int


class MetricsOut(BaseModel):
    ttd_avg: Optional[float] = None
    ttr_avg: Optional[float] = None
    alerts_suppressed: int = 0
    band_counts: Dict[str, int]
    events_over_time: List[Dict[str, Any]]
    top_honeypots: List[Dict[str, Any]]
    top_attack_types: List[Dict[str, Any]]
    last_20_ttd: List[float] = Field(default_factory=list)
    last_20_ttr: List[float] = Field(default_factory=list)


class WSMessage(BaseModel):
    type: str
    payload: Dict[str, Any]

