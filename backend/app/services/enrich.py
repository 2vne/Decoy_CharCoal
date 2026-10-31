from __future__ import annotations
from typing import Any, Dict
import httpx
from app.config import settings

_cache: Dict[str, Dict[str, Any]] = {}


async def get_abuseipdb(ip: str) -> Dict[str, Any]:
    if not settings.abuseipdb_key or settings.mock_mode:
        return {"reputation": 0, "totalReports": 0, "source": "mock"}

    cache_key = f"abuse:{ip}"
    if cache_key in _cache:
        return _cache[cache_key]

    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            r = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": settings.abuseipdb_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
            if r.status_code == 200:
                data = r.json().get("data", {})
                result = {
                    "reputation": data.get("abuseConfidenceScore", 0),
                    "totalReports": data.get("totalReports", 0),
                    "source": "abuseipdb",
                }
                _cache[cache_key] = result
                return result
    except Exception:
        pass

    return {"reputation": 0, "totalReports": 0, "source": "error"}


async def get_virustotal(ip: str) -> Dict[str, Any]:
    if not settings.virustotal_key or settings.mock_mode:
        return {"malicious": 0, "suspicious": 0, "source": "mock"}

    cache_key = f"vt:{ip}"
    if cache_key in _cache:
        return _cache[cache_key]

    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            r = await client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": settings.virustotal_key},
            )
            if r.status_code == 200:
                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                result = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "source": "virustotal",
                }
                _cache[cache_key] = result
                return result
    except Exception:
        pass

    return {"malicious": 0, "suspicious": 0, "source": "error"}


async def enrich_ip(ip: str) -> Dict[str, Any]:
    abuse = await get_abuseipdb(ip)
    vt = await get_virustotal(ip)
    return {"abuseipdb": abuse, "virustotal": vt}

