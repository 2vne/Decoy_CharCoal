from __future__ import annotations
import re
from typing import Any, Dict
from app.schemas import EventIn

URL_REGEX = re.compile(r'https?://[^\s\'"<>]+')
VALID_TYPES = {
    "connect", "login_failed", "login_success", "command",
    "file_download", "file_upload", "scan", "exploit", "close", "other"
}


def normalise_event(event: EventIn) -> Dict[str, Any]:
    raw_type = (event.event_type or "").strip().lower()
    event_type = raw_type if raw_type in VALID_TYPES else "other"

    honeypot = (event.honeypot or "").strip().lower()
    decoy_type = (event.decoy_type or "external").strip().lower()
    src_ip = (event.src_ip or "").strip()

    command = event.command.strip() if event.command else None
    username = event.username.strip() if event.username else None
    password = event.password if event.password else None

    extracted_urls = []
    if command:
        extracted_urls = URL_REGEX.findall(command)

    url = event.url.strip() if event.url else (extracted_urls[0] if extracted_urls else None)

    return {
        "event_type": event_type,
        "honeypot": honeypot,
        "decoy_type": decoy_type,
        "src_ip": src_ip,
        "command": command,
        "username": username,
        "password": password,
        "url": url,
        "extracted_urls": extracted_urls,
    }

