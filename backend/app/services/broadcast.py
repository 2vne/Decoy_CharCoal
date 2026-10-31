from __future__ import annotations
import json
import logging
from typing import Any, List
from fastapi import WebSocket

logger = logging.getLogger(__name__)

_connections: List[WebSocket] = []


async def connect(ws: WebSocket) -> None:
    await ws.accept()
    _connections.append(ws)
    logger.info(f"WebSocket client connected. Total clients: {len(_connections)}")


def disconnect(ws: WebSocket) -> None:
    if ws in _connections:
        _connections.remove(ws)
        logger.info(f"WebSocket client disconnected. Total clients: {len(_connections)}")


async def broadcast(msg_type: str, payload: Any) -> None:
    if not _connections:
        return

    message = json.dumps({"type": msg_type, "payload": payload})
    dead = []
    for ws in list(_connections):
        try:
            await ws.send_text(message)
        except Exception:
            dead.append(ws)

    for ws in dead:
        disconnect(ws)

