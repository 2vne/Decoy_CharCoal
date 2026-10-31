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

    @field_validator("safe_ips", mode="before")
    @classmethod
    def parse_safe_ips(cls, v):
        if isinstance(v, str):
            return [ip.strip() for ip in v.split(",") if ip.strip()]
        return v


settings = Settings()

