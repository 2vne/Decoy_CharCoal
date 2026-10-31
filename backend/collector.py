import os
import json
import time
import hashlib
import ipaddress
from pathlib import Path
from datetime import datetime, timezone

import httpx
from dotenv import dotenv_values

HOME = Path.home()
ENV = dotenv_values(Path(__file__).parent / ".env")
API_KEY = ENV.get("API_KEY") or os.environ.get("API_KEY", "changeme")

API_URL = os.environ.get("SENTINEL_API_URL", "http://127.0.0.1:8000/api/events")
STATE_FILE = Path(__file__).parent / ".collector_state.json"

SOURCES = {
    "cowrie": HOME / "honeynet/logs/cowrie/cowrie.json",
    "opencanary": HOME / "honeynet/logs/opencanary/opencanary.log",
    "dionaea": HOME / "honeynet/dionaea/data/dionaea/dionaea.json",
}

def load_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    # Start at the end of existing files; process new events only.
    return {
        name: {"offset": path.stat().st_size, "inode": path.stat().st_ino}
        for name, path in SOURCES.items()
        if path.exists()
    }

def save_state(state):
    temp = STATE_FILE.with_suffix(".tmp")
    temp.write_text(json.dumps(state))
    temp.replace(STATE_FILE)

def timestamp(value):
    if not value:
        return datetime.now(timezone.utc).isoformat()
    value = str(value).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(value)
    except Exception:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()

def event_id(source, line):
    return hashlib.sha256(source.encode() + line).hexdigest()

def traffic_scope(ip):
    try:
        address = ipaddress.ip_address(ip)
        return "internal_test" if (
            address.is_private or address.is_loopback
        ) else "external"
    except ValueError:
        return "unknown"

def convert(source, e, line):
    src = e.get("src_ip") or e.get("src_host")
    if not src:
        return None

    try:
        ipaddress.ip_address(src)
    except ValueError:
        return None

    event_type = "other"
    decoy = source
    session = None
    username = None
    protocol = None
    ts = None
    dst_port = e.get("dst_port")
    src_port = e.get("src_port")

    if source == "cowrie":
        kind = e.get("eventid", "")

        mapping = {
            "cowrie.session.connect": "connect",
            "cowrie.login.failed": "login_failed",
            "cowrie.login.success": "login_success",
            "cowrie.command.input": "command",
            "cowrie.session.closed": "close",
        }
        if kind not in mapping:
            return None

        event_type = mapping[kind]
        session = e.get("session")
        username = e.get("username")
        protocol = e.get("protocol")
        ts = e.get("timestamp")
        decoy = protocol or "ssh"

    elif source == "opencanary":
        # Ignore startup/configuration messages.
        if str(e.get("logtype")) == "1001":
            return None
        if not isinstance(src_port, int) or src_port < 0:
            return None
        if not isinstance(dst_port, int) or dst_port < 1:
            return None
        event_type = "other"
        ts = e.get("utc_time")

    elif source == "dionaea":
        connection = e.get("connection", {})
        protocol = connection.get("protocol")
        kind = connection.get("type")

        if kind == "accept":
            event_type = "connect"
        elif kind == "close":
            event_type = "close"
        else:
            return None

        ts = e.get("timestamp")
        decoy = protocol or "network"

    raw = {
        "source_scope": traffic_scope(src),
        "protocol": protocol,
    }

    return {
        "event_id": event_id(source, line),
        "timestamp": timestamp(ts),
        "honeypot": source,
        "decoy_type": decoy,
        "src_ip": src,
        "src_port": src_port if isinstance(src_port, int) and src_port >= 0 else None,
        "dst_port": dst_port if isinstance(dst_port, int) and dst_port >= 0 else None,
        "session_id": session,
        "event_type": event_type,
        "username": username,
        "raw": raw,
    }

def process_file(source, path, state, client):
    if not path.exists():
        return

    current_inode = path.stat().st_ino
    entry = state.get(source)

    if entry is None:
        # New source: start with future events, not historical records.
        state[source] = {
            "offset": path.stat().st_size,
            "inode": current_inode,
        }
        return

    if entry["inode"] != current_inode or path.stat().st_size < entry["offset"]:
        entry["offset"] = 0
        entry["inode"] = current_inode

    with path.open("rb") as f:
        f.seek(entry["offset"])
        data = f.read()

    # Process complete lines only.
    last_newline = data.rfind(b"\n")
    if last_newline < 0:
        return

    complete = data[:last_newline + 1]
    entry["offset"] += len(complete)

    for line in complete.splitlines():
        if not line.strip():
            continue

        try:
            e = json.loads(line)
            event = convert(source, e, line)
            if event is None:
                continue

            response = client.post(API_URL, json=event)
            response.raise_for_status()
            print(f"Sent {source}: {event['event_type']} [{event['src_ip']}]")

        except Exception as exc:
            print(f"{source}: event processing failed ({type(exc).__name__})")

def main():
    state = load_state()

    for name, path in SOURCES.items():
        if name not in state and path.exists():
            state[name] = {
                "offset": path.stat().st_size,
                "inode": path.stat().st_ino,
            }

    save_state(state)

    print("SENTINEL collector started.")
    print("Watching Cowrie, OpenCanary and Dionaea.")
    print("Historical logs skipped; waiting for new events.")

    headers = {"X-API-Key": API_KEY}

    with httpx.Client(headers=headers, timeout=10) as client:
        while True:
            for source, path in SOURCES.items():
                try:
                    process_file(source, path, state, client)
                    save_state(state)
                except Exception as exc:
                    print(f"{source}: collector error ({type(exc).__name__})")

            time.sleep(2)

if __name__ == "__main__":
    main()

