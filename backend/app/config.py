from __future__ import annotations
import os
from typing import List, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    api_key: str = "changeme"
    database_url: str = "sqlite+aiosqlite:///./sentinel.db"
    mock_mode: bool = True
    seed_demo: bool = True
    safe_ips: Union[List[str], str] = ["127.0.0.1", "::1"]
    require_approval: bool = True
    enforcer_url: str = ""
    enforcer_token: str = ""
    health_url: str = ""
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    abuseipdb_key: str = ""
    virustotal_key: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    pagerduty_routing_key: str = ""
    pagerduty_phone: str = "9372185727"
    twilio_account_sid: str = ""
    twilio_auth_token: str = ""
    twilio_phone_number: str = ""
    twilio_test_verified_number: str = ""
    twilio_to_number: str = "8652477694"
    resend_api_key: str = ""
    authority_email: str = "danishsjain@gmail.com"
    frontend_origin: str = "http://localhost:3000"

    # Level-2 Function-Level Attack Intelligence Configuration
    function_weights: dict = {
        "auth_login": 10,
        "auth_otp": 15,
        "auth_reset": 12,
        "admin_access": 20,
        "payment_gateway": 25,
        "database_api": 25,
        "secrets_env": 30,
    }
    behavioural_windows: List[int] = [30, 60, 300, 900]
    function_risk_thresholds: dict = {
        "low": 30.0,
        "medium": 70.0,
        "high": 100.0,
    }

    # 0-100 Behaviour-Based Risk Scoring Configuration (Total must equal 100)
    behaviour_point_allocation: dict = {
        "login_failures": 12,
        "otp_failures": 8,
        "password_reset": 5,
        "admin_access": 15,
        "secrets_probing": 20,
        "endpoint_enumeration": 15,
        "abnormal_rate": 10,
        "database_access": 10,
        "combined_patterns": 5,
    }

    # Rolling observation windows (seconds)
    observation_windows: dict = {
        "auth": 600,         # 10 minutes for authentication behaviour
        "probe": 600,        # 10 minutes for endpoint and secrets probing
        "rate": 60,          # 1 minute for request frequency
        "session": 1800,     # 30 minutes for broader session behaviour
    }

    # Classification thresholds: 0-29 NORMAL, 30-49 SUSPICIOUS, 50-69 HIGH_RISK, 70-100 LIKELY_MALICIOUS
    classification_thresholds: dict = {
        "NORMAL": 29.99,
        "SUSPICIOUS": 49.99,
        "HIGH_RISK": 69.99,
        "LIKELY_MALICIOUS": 100.0,
    }

    # Decoy routing safeguards
    decoy_routing_threshold: float = 70.0
    decoy_min_independent_categories: int = 2
    emergency_single_vector_divert: bool = False

    # Event-Triggered Dynamic Session Diversion
    critical_event_immediate_divert: bool = True
    critical_event_types: list = [
        "secrets_probe",
        "git_probe",
        "payment_manipulation",
        "unauthorized_db_probe",
        "admin_escalation",
        "config_probe",
    ]
    critical_event_categories: list = [
        "secrets_probing",
        "database_access",
    ]

    # Controlled Decoy Latency and Attacker Behaviour Observation
    decoy_latency_enabled: bool = True
    decoy_max_concurrent_delayed_requests: int = 50
    decoy_latency_profiles: dict = {
        "landing": {"min": 0.0, "max": 0.3},          # Landing page: 0–300 ms
        "auth_login": {"min": 1.0, "max": 2.0},       # Fake login: 1–2 seconds
        "auth_otp": {"min": 2.0, "max": 3.0},         # Fake OTP: 2–3 seconds
        "auth_reset": {"min": 1.0, "max": 2.0},       # Fake password reset: 1–2 seconds
        "admin_console": {"min": 2.0, "max": 4.0},    # Fake admin console: 2–4 seconds
        "database_api": {"min": 2.0, "max": 5.0},     # Fake customer/database API: 2–5 seconds
        "payment_gateway": {"min": 3.0, "max": 5.0},  # Fake payment gateway: 3–5 seconds
        "honeytoken": {"min": 1.0, "max": 3.0},       # Honeytoken interactions: 1–3 seconds
        "default": {"min": 0.2, "max": 0.8},
    }

    # Remediation Advisor & Gateway Lifecycle Configuration
    watch_window_min: int = 120
    reattack_window_min: int = 60
    watch_threshold_drop: float = 0.20
    verify_targets: str = "http://127.0.0.1:8000,http://localhost:8000"
    smtp_host: str = ""
    smtp_user: str = ""
    smtp_pass: str = ""
    smtp_to: str = "danishsjain@gmail.com"

    @field_validator("safe_ips", mode="before")
    @classmethod
    def parse_safe_ips(cls, v):
        if isinstance(v, str):
            return [ip.strip() for ip in v.split(",") if ip.strip()]
        return v


settings = Settings()

