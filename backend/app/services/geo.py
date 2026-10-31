from __future__ import annotations
import hashlib
import ipaddress
from typing import Any, Dict
import httpx
from app.config import settings

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

_cache: Dict[str, Dict[str, Any]] = {}


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_RANGES)
    except ValueError:
        return False


def _fake_geo(ip: str) -> Dict[str, Any]:
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    countries = ["US", "CN", "RU", "DE", "BR", "IN", "KR", "FR", "GB", "NL"]
    cities = ["New York", "Beijing", "Moscow", "Berlin", "São Paulo", "Mumbai", "Seoul", "Paris", "London", "Amsterdam"]
    idx = h % len(countries)
    lat = ((h % 14000) - 7000) / 100.0
    lon = ((h % 36000) - 18000) / 100.0
    return {
        "status": "success",
        "country": countries[idx],
        "countryCode": countries[idx],
        "city": cities[idx],
        "lat": lat,
        "lon": lon,
        "isp": "Autonomous System Mock",
        "org": f"SOC-DECEPTION-{countries[idx]}",
        "query": ip,
    }


async def get_geo(ip: str) -> Dict[str, Any]:
    if ip in _cache:
        return _cache[ip]

    if _is_private(ip) or settings.mock_mode:
        geo = _fake_geo(ip)
        _cache[ip] = geo
        return geo

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,org,query"
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("status") == "success":
                    _cache[ip] = data
                    return data
    except Exception:
        pass

    geo = _fake_geo(ip)
    _cache[ip] = geo
    return geo

