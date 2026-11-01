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

    @field_validator("safe_ips", mode="before")
    @classmethod
    def parse_safe_ips(cls, v):
        if isinstance(v, str):
            return [ip.strip() for ip in v.split(",") if ip.strip()]
        return v


settings = Settings()

