from __future__ import annotations
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.services.broadcast import connect, disconnect

router = APIRouter()
logger = logging.getLogger(__name__)


@router.websocket("/ws/live")
async def websocket_live_endpoint(websocket: WebSocket):
    await connect(websocket)
    try:
        while True:
            # Client can send ping/pong or queries
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text('{"type":"pong"}')
    except WebSocketDisconnect:
        disconnect(websocket)
    except Exception as e:
        logger.debug(f"WebSocket client disconnected: {e}")
        disconnect(websocket)

