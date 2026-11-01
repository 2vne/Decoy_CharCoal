from __future__ import annotations
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.services.assistant import (
    ASSISTANT_TOOLS_SPEC,
    chat_with_assistant,
    execute_tool,
)
from app.services.audit import record_audit

router = APIRouter(prefix="/assistant", tags=["SOC Intelligent Assistant"])


class ChatMessageTurn(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str
    conversation_history: Optional[List[ChatMessageTurn]] = []


class ExecuteToolRequest(BaseModel):
    tool_name: str
    arguments: Optional[Dict[str, Any]] = {}


class ConfirmActionRequest(BaseModel):
    action_type: str
    payload: Dict[str, Any]
    confirmed: bool


@router.get("/tools")
async def list_available_tools():
    """
    Returns the list of 9 registered read-only investigation tools available to the assistant.
    """
    return {
        "count": len(ASSISTANT_TOOLS_SPEC),
        "tools": ASSISTANT_TOOLS_SPEC,
    }


@router.post("/chat")
async def assistant_chat(
    req: ChatRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Conversational endpoint: processes natural language inquiries, executes live backend tools,
    and returns factual evidence-backed security briefings.
    """
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    history_dicts = [{"role": t.role, "content": t.content} for t in (req.conversation_history or [])]
    result = await chat_with_assistant(
        message=req.message,
        conversation_history=history_dicts,
        db=db,
    )
    return result


@router.post("/execute-tool")
async def run_tool_directly(
    req: ExecuteToolRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Directly executes an investigation tool against live backend databases.
    """
    result = await execute_tool(req.tool_name, req.arguments or {}, db)
    return {
        "tool_name": req.tool_name,
        "result": result,
    }


@router.post("/confirm-action")
async def confirm_security_action(
    req: ConfirmActionRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Executes a security-modifying action (e.g. block IP, reset session) ONLY after explicit analyst confirmation.
    """
    if not req.confirmed:
        return {
            "status": "cancelled",
            "message": "Action was cancelled by the security analyst.",
        }

    action_type = req.action_type
    payload = req.payload

    if action_type == "block_ip":
        target_ip = payload.get("ip")
        if not target_ip:
            raise HTTPException(status_code=400, detail="Missing target IP for block action")
        
        from app.services.enforcer import block_attacker
        block_result = await block_attacker(
            ip=target_ip,
            reason=payload.get("reason", "Analyst confirmed action via Sentinel Assistant"),
            duration_minutes=payload.get("duration_minutes", 60),
            db=db,
        )
        
        await record_audit(
            db=db,
            entity_type="attacker",
            entity_id=target_ip,
            action="enforce_block",
            actor="analyst_via_assistant",
            details=block_result,
        )
        await db.commit()

        return {
            "status": "executed",
            "action_type": action_type,
            "target": target_ip,
            "result": block_result,
            "message": f"Successfully enforced firewall block on {target_ip}.",
        }

    elif action_type == "reset_session":
        from sqlalchemy import delete, select
        from app.models import ObservedBehaviourEvent, VisitorSessionRisk
        from app.demo_apps.real_app import REVOKED_SESSIONS
        
        session_id = payload.get("session_id", "demo_session").strip()
        REVOKED_SESSIONS.discard(session_id)
        
        del_stmt = delete(ObservedBehaviourEvent).where(ObservedBehaviourEvent.session_id == session_id)
        await db.execute(del_stmt)
        
        sess_stmt = select(VisitorSessionRisk).where(VisitorSessionRisk.session_id == session_id)
        sess_res = await db.execute(sess_stmt)
        sess = sess_res.scalar_one_or_none()
        if sess:
            await db.delete(sess)
        
        await record_audit(
            db=db,
            entity_type="session",
            entity_id=session_id,
            action="reset_session",
            actor="analyst_via_assistant",
            details={"session_id": session_id},
        )
        await db.commit()

        return {
            "status": "executed",
            "action_type": action_type,
            "target": session_id,
            "message": f"Successfully reset threat markers for session {session_id}.",
        }

    else:
        raise HTTPException(status_code=400, detail=f"Unsupported action type: {action_type}")
