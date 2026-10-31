from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(sa.String(64), unique=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utc_now)
    honeypot: Mapped[str] = mapped_column(sa.String(32), index=True)
    decoy_type: Mapped[str] = mapped_column(sa.String(32), default="external")
    src_ip: Mapped[str] = mapped_column(sa.String(64), index=True)
    src_port: Mapped[Optional[int]] = mapped_column(sa.Integer, nullable=True)
    dst_port: Mapped[Optional[int]] = mapped_column(sa.Integer, nullable=True)
    session_id: Mapped[Optional[str]] = mapped_column(sa.String(128), nullable=True)
    event_type: Mapped[str] = mapped_column(sa.String(64), index=True)
    username: Mapped[Optional[str]] = mapped_column(sa.String(128), nullable=True)
    password: Mapped[Optional[str]] = mapped_column(sa.String(256), nullable=True)
    command: Mapped[Optional[str]] = mapped_column(sa.Text, nullable=True)
    url: Mapped[Optional[str]] = mapped_column(sa.Text, nullable=True)
    file_hash: Mapped[Optional[str]] = mapped_column(sa.String(128), nullable=True)
    raw: Mapped[Dict[str, Any]] = mapped_column(sa.JSON, default=dict)
    normalised: Mapped[Optional[Dict[str, Any]]] = mapped_column(sa.JSON, nullable=True)
    raw_hash: Mapped[Optional[str]] = mapped_column(sa.String(64), nullable=True, index=True)
    chain_hash: Mapped[Optional[str]] = mapped_column(sa.String(64), nullable=True, index=True)
    prev_hash: Mapped[Optional[str]] = mapped_column(sa.String(64), nullable=True)
    attacker_id: Mapped[Optional[int]] = mapped_column(sa.Integer, sa.ForeignKey("attackers.id"), nullable=True)


class Attacker(Base):
    __tablename__ = "attackers"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(sa.String(64), unique=True, index=True)
    first_seen: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utc_now)
    last_seen: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utc_now)
    total_events: Mapped[int] = mapped_column(sa.Integer, default=0)
    honeypots_touched: Mapped[List[str]] = mapped_column(sa.JSON, default=list)
    ports: Mapped[List[int]] = mapped_column(sa.JSON, default=list)
    usernames: Mapped[List[str]] = mapped_column(sa.JSON, default=list)
    passwords: Mapped[List[str]] = mapped_column(sa.JSON, default=list)
    commands: Mapped[List[str]] = mapped_column(sa.JSON, default=list)
    urls: Mapped[List[str]] = mapped_column(sa.JSON, default=list)
    hashes: Mapped[List[str]] = mapped_column(sa.JSON, default=list)
    sessions: Mapped[List[str]] = mapped_column(sa.JSON, default=list)
    is_repeat: Mapped[bool] = mapped_column(sa.Boolean, default=False)
    status: Mapped[str] = mapped_column(sa.String(32), default="active")  # active, blocked, watchlist
    fingerprint: Mapped[Optional[str]] = mapped_column(sa.String(128), nullable=True, index=True)
    feature_vector: Mapped[Optional[Dict[str, Any]]] = mapped_column(sa.JSON, nullable=True)
    risk_score: Mapped[float] = mapped_column(sa.Float, default=0.0)
    risk_band: Mapped[str] = mapped_column(sa.String(32), default="low")
    risk_factors: Mapped[List[Dict[str, Any]]] = mapped_column(sa.JSON, default=list)
    risk_history: Mapped[List[Dict[str, Any]]] = mapped_column(sa.JSON, default=list)
    intent: Mapped[Optional[str]] = mapped_column(sa.String(64), nullable=True)
    intent_evidence: Mapped[List[str]] = mapped_column(sa.JSON, default=list)
    is_anomaly: Mapped[bool] = mapped_column(sa.Boolean, default=False)
    anomaly_score: Mapped[Optional[float]] = mapped_column(sa.Float, nullable=True)
    targeted_functions: Mapped[List[str]] = mapped_column(sa.JSON, default=list)
    function_risk_score: Mapped[float] = mapped_column(sa.Float, default=0.0)
    function_risk_breakdown: Mapped[Dict[str, Any]] = mapped_column(sa.JSON, default=dict)


class Relationship(Base):
    __tablename__ = "relationships"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    attacker_a_id: Mapped[int] = mapped_column(sa.Integer, sa.ForeignKey("attackers.id"), index=True)
    attacker_b_id: Mapped[int] = mapped_column(sa.Integer, sa.ForeignKey("attackers.id"), index=True)
    rel_type: Mapped[str] = mapped_column(sa.String(64))  # same_fingerprint, shared_credentials, shared_malware, same_honeypot_window
    weight: Mapped[float] = mapped_column(sa.Float, default=1.0)
    evidence: Mapped[List[str]] = mapped_column(sa.JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utc_now)


class MitreMapping(Base):
    __tablename__ = "mitre_mappings"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    attacker_id: Mapped[int] = mapped_column(sa.Integer, sa.ForeignKey("attackers.id"), index=True)
    technique_id: Mapped[str] = mapped_column(sa.String(32), index=True)
    technique_name: Mapped[str] = mapped_column(sa.String(128))
    tactic: Mapped[str] = mapped_column(sa.String(64))
    evidence_event_ids: Mapped[List[str]] = mapped_column(sa.JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utc_now)


class KillChainMapping(Base):
    __tablename__ = "killchain_mappings"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    attacker_id: Mapped[int] = mapped_column(sa.Integer, sa.ForeignKey("attackers.id"), index=True)
    phase: Mapped[str] = mapped_column(sa.String(64), index=True)
    evidence_event_ids: Mapped[List[str]] = mapped_column(sa.JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utc_now)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    attacker_id: Mapped[Optional[int]] = mapped_column(sa.Integer, sa.ForeignKey("attackers.id"), nullable=True)
    src_ip: Mapped[str] = mapped_column(sa.String(64), index=True)
    honeypot: Mapped[str] = mapped_column(sa.String(32), index=True)
    event_type: Mapped[str] = mapped_column(sa.String(64))
    classification: Mapped[Optional[str]] = mapped_column(sa.String(64), nullable=True)
    count: Mapped[int] = mapped_column(sa.Integer, default=1)
    first_seen: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utc_now)
    last_seen: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utc_now)
    alerts_suppressed: Mapped[int] = mapped_column(sa.Integer, default=0)
    event_ids: Mapped[List[str]] = mapped_column(sa.JSON, default=list)


class Block(Base):
    __tablename__ = "blocks"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(sa.String(64), index=True)
    attacker_id: Mapped[Optional[int]] = mapped_column(sa.Integer, sa.ForeignKey("attackers.id"), nullable=True)
    requested_by: Mapped[str] = mapped_column(sa.String(64), default="system")
    ttl_seconds: Mapped[int] = mapped_column(sa.Integer, default=600)
    status: Mapped[str] = mapped_column(sa.String(32), default="pending")  # pending, active, expired, rolled_back, failed
    requested_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utc_now)
    verified_at: Mapped[Optional[datetime]] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    rolled_back_at: Mapped[Optional[datetime]] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    mock: Mapped[bool] = mapped_column(sa.Boolean, default=False)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    attacker_id: Mapped[Optional[int]] = mapped_column(sa.Integer, sa.ForeignKey("attackers.id"), nullable=True)
    title: Mapped[str] = mapped_column(sa.String(256))
    status: Mapped[str] = mapped_column(sa.String(32), default="new")  # new, investigating, contained, resolved
    status_history: Mapped[List[Dict[str, Any]]] = mapped_column(sa.JSON, default=list)
    assignee: Mapped[Optional[str]] = mapped_column(sa.String(64), nullable=True)
    notes: Mapped[List[Dict[str, Any]]] = mapped_column(sa.JSON, default=list)
    root_cause: Mapped[Dict[str, Any]] = mapped_column(sa.JSON, default=dict)
    blast_radius: Mapped[Dict[str, Any]] = mapped_column(sa.JSON, default=dict)
    ttd_seconds: Mapped[Optional[float]] = mapped_column(sa.Float, nullable=True)
    ttr_seconds: Mapped[Optional[float]] = mapped_column(sa.Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utc_now)
    risk_score_at_creation: Mapped[float] = mapped_column(sa.Float, default=0.0)
    ai_investigation: Mapped[Optional[Dict[str, Any]]] = mapped_column(sa.JSON, nullable=True)


class ResponseAction(Base):
    __tablename__ = "actions"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    attacker_id: Mapped[Optional[int]] = mapped_column(sa.Integer, sa.ForeignKey("attackers.id"), nullable=True, index=True)
    incident_id: Mapped[Optional[int]] = mapped_column(sa.Integer, sa.ForeignKey("incidents.id"), nullable=True, index=True)
    block_id: Mapped[Optional[int]] = mapped_column(sa.Integer, sa.ForeignKey("blocks.id"), nullable=True)
    action_type: Mapped[str] = mapped_column(sa.String(64), default="firewall_block")  # firewall_block, rate_limit, isolate, honeypot_divert
    target_ip: Mapped[str] = mapped_column(sa.String(64), index=True)
    status: Mapped[str] = mapped_column(sa.String(32), default="proposed")  # proposed, approved, rejected, executed, verified, rolled_back
    reason: Mapped[str] = mapped_column(sa.String(256))
    duration_seconds: Mapped[int] = mapped_column(sa.Integer, default=600)
    approver: Mapped[Optional[str]] = mapped_column(sa.String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utc_now)
    approved_at: Mapped[Optional[datetime]] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    rejected_at: Mapped[Optional[datetime]] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    executed_at: Mapped[Optional[datetime]] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    verified_at: Mapped[Optional[datetime]] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    rolled_back_at: Mapped[Optional[datetime]] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    details: Mapped[Dict[str, Any]] = mapped_column(sa.JSON, default=dict)


class NotificationLog(Base):
    __tablename__ = "notification_logs"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    attacker_id: Mapped[Optional[int]] = mapped_column(sa.Integer, sa.ForeignKey("attackers.id"), nullable=True, index=True)
    target_ip: Mapped[str] = mapped_column(sa.String(64), default="")
    channel: Mapped[str] = mapped_column(sa.String(32))  # telegram, pagerduty, smtp
    severity: Mapped[str] = mapped_column(sa.String(32))  # high, critical
    recipient: Mapped[str] = mapped_column(sa.String(128), default="")
    payload: Mapped[Dict[str, Any]] = mapped_column(sa.JSON, default=dict)
    status: Mapped[str] = mapped_column(sa.String(32), default="sent")  # sent, suppressed, failed, simulated
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utc_now)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    entity_type: Mapped[str] = mapped_column(sa.String(64), index=True)  # incident, action, block, event, system
    entity_id: Mapped[str] = mapped_column(sa.String(128), index=True)
    action: Mapped[str] = mapped_column(sa.String(128))  # status_change, approval, rejection, execution, rollback, note_added
    actor: Mapped[str] = mapped_column(sa.String(64), default="system")
    details: Mapped[Dict[str, Any]] = mapped_column(sa.JSON, default=dict)
    timestamp: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utc_now)


class ExposureAsset(Base):
    __tablename__ = "exposure_assets"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(sa.String(128), unique=True)
    asset_type: Mapped[str] = mapped_column(sa.String(64))  # database, scada_plc, ssh_bastion, web_portal, internal_ad
    honeypot_link: Mapped[str] = mapped_column(sa.String(32))  # cowrie, opencanary, dionaea, conpot
    criticality: Mapped[str] = mapped_column(sa.String(32), default="high")  # low, medium, high, critical
    exposure_score: Mapped[float] = mapped_column(sa.Float, default=0.0)
    threshold: Mapped[float] = mapped_column(sa.Float, default=65.0)
    breached: Mapped[bool] = mapped_column(sa.Boolean, default=False)
    last_evaluated: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utc_now)


class ActionLog(Base):
    __tablename__ = "action_logs"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    attacker_id: Mapped[Optional[int]] = mapped_column(sa.Integer, sa.ForeignKey("attackers.id"), nullable=True)
    action_type: Mapped[str] = mapped_column(sa.String(64))  # log, watchlist, notify, recommend_block, incident, block
    level: Mapped[int] = mapped_column(sa.Integer, default=1)
    details: Mapped[Dict[str, Any]] = mapped_column(sa.JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utc_now)


class MetricSnapshot(Base):
    __tablename__ = "metric_snapshots"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utc_now)
    events_count: Mapped[int] = mapped_column(sa.Integer, default=0)
    attackers_count: Mapped[int] = mapped_column(sa.Integer, default=0)
    incidents_count: Mapped[int] = mapped_column(sa.Integer, default=0)
    blocks_count: Mapped[int] = mapped_column(sa.Integer, default=0)
    alerts_suppressed: Mapped[int] = mapped_column(sa.Integer, default=0)
    band_counts: Mapped[Dict[str, int]] = mapped_column(sa.JSON, default=lambda: {"low": 0, "medium": 0, "high": 0, "critical": 0})


class FunctionTargetEvent(Base):
    __tablename__ = "function_target_events"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    attacker_id: Mapped[int] = mapped_column(sa.Integer, sa.ForeignKey("attackers.id"), index=True)
    src_ip: Mapped[str] = mapped_column(sa.String(64), index=True)
    target_function: Mapped[str] = mapped_column(sa.String(64), index=True)
    target_endpoint: Mapped[str] = mapped_column(sa.String(256), default="")
    attack_type: Mapped[str] = mapped_column(sa.String(64), default="probe")
    severity: Mapped[str] = mapped_column(sa.String(32), default="medium")
    result: Mapped[str] = mapped_column(sa.String(32), default="intercepted")
    attempts: Mapped[int] = mapped_column(sa.Integer, default=1)
    honeypot_source: Mapped[str] = mapped_column(sa.String(64), default="gateway")
    evidence: Mapped[str] = mapped_column(sa.Text, default="")
    confidence: Mapped[float] = mapped_column(sa.Float, default=1.0)
    is_simulated: Mapped[bool] = mapped_column(sa.Boolean, default=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utc_now)


class GatewayRequestLog(Base):
    __tablename__ = "gateway_request_logs"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    src_ip: Mapped[str] = mapped_column(sa.String(64), index=True)
    method: Mapped[str] = mapped_column(sa.String(16), default="GET")
    path: Mapped[str] = mapped_column(sa.String(256), index=True)
    routed_to: Mapped[str] = mapped_column(sa.String(32), index=True)  # real, decoy, challenge, blocked
    risk_score: Mapped[float] = mapped_column(sa.Float, default=0.0)
    decision_reason: Mapped[str] = mapped_column(sa.Text, default="")
    status_code: Mapped[int] = mapped_column(sa.Integer, default=200)
    response_time_ms: Mapped[float] = mapped_column(sa.Float, default=0.0)
    timestamp: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utc_now, index=True)


class GatewayIncident(Base):
    __tablename__ = "gateway_incidents"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    incident_uuid: Mapped[str] = mapped_column(sa.String(64), unique=True, index=True)
    endpoint: Mapped[str] = mapped_column(sa.String(256), index=True)
    status: Mapped[str] = mapped_column(sa.String(32), default="active")  # active, mitigated, resolved, investigating
    severity: Mapped[str] = mapped_column(sa.String(16), default="high")  # low, medium, high, critical
    error_code: Mapped[int] = mapped_column(sa.Integer, default=502)
    first_failure_ts: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utc_now)
    detection_ts: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utc_now)
    last_failure_ts: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utc_now)
    recovery_ts: Mapped[Optional[datetime]] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    recurrence_count: Mapped[int] = mapped_column(sa.Integer, default=1)
    related_attacker_ip: Mapped[Optional[str]] = mapped_column(sa.String(64), nullable=True)
    related_function: Mapped[Optional[str]] = mapped_column(sa.String(64), nullable=True)
    error_details: Mapped[str] = mapped_column(sa.Text, default="")
    evidence: Mapped[Dict[str, Any]] = mapped_column(sa.JSON, default=dict)
    ai_investigation: Mapped[Optional[Dict[str, Any]]] = mapped_column(sa.JSON, nullable=True)


class CommitAttribution(Base):
    __tablename__ = "commit_attributions"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[Optional[int]] = mapped_column(sa.Integer, sa.ForeignKey("gateway_incidents.id"), nullable=True)
    commit_hash: Mapped[str] = mapped_column(sa.String(64), index=True)
    author_name: Mapped[str] = mapped_column(sa.String(128))
    author_email: Mapped[str] = mapped_column(sa.String(128))
    commit_msg: Mapped[str] = mapped_column(sa.Text)
    commit_ts: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
    changed_files: Mapped[List[str]] = mapped_column(sa.JSON, default=list)
    related_function: Mapped[str] = mapped_column(sa.String(64), default="")
    assigned_team: Mapped[str] = mapped_column(sa.String(64), default="backend")  # backend, frontend, database, devops, security, payments
    confidence: Mapped[float] = mapped_column(sa.Float, default=0.8)
    correlation_explanation: Mapped[str] = mapped_column(sa.Text, default="")



