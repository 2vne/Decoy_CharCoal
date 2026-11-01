from __future__ import annotations
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase
from app.config import settings


class Base(DeclarativeBase):
    pass


connect_args = {}
if settings.database_url.startswith("sqlite"):
    connect_args["check_same_thread"] = False

async_engine = create_async_engine(
    settings.database_url,
    connect_args=connect_args,
    echo=False,
)

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session


import sqlalchemy as sa

async def safe_migrate(conn_or_session) -> None:
    """
    Safely adds new columns to existing database tables if they do not exist.
    Prevents OperationalError without requiring table resets or drops.
    Compatible with both AsyncConnection and AsyncSession.
    """
    def _do_inspect(sync_obj):
        # Extract underlying Connection if a Session is provided
        conn = sync_obj.connection() if hasattr(sync_obj, "connection") and callable(sync_obj.connection) else sync_obj
        inspector = sa.inspect(conn)
        tables = inspector.get_table_names()

        # Check attackers table
        if "attackers" in tables:
            cols = {c["name"] for c in inspector.get_columns("attackers")}
            if "targeted_functions" not in cols:
                conn.execute(sa.text("ALTER TABLE attackers ADD COLUMN targeted_functions JSON DEFAULT '[]'"))
            if "function_risk_score" not in cols:
                conn.execute(sa.text("ALTER TABLE attackers ADD COLUMN function_risk_score FLOAT DEFAULT 0.0"))
            if "function_risk_breakdown" not in cols:
                conn.execute(sa.text("ALTER TABLE attackers ADD COLUMN function_risk_breakdown JSON DEFAULT '{}'"))

        # Check function_target_events table
        if "function_target_events" in tables:
            cols = {c["name"] for c in inspector.get_columns("function_target_events")}
            if "is_simulated" not in cols:
                conn.execute(sa.text("ALTER TABLE function_target_events ADD COLUMN is_simulated BOOLEAN DEFAULT 0"))
            if "confidence" not in cols:
                conn.execute(sa.text("ALTER TABLE function_target_events ADD COLUMN confidence FLOAT DEFAULT 1.0"))
            if "session_id" not in cols:
                conn.execute(sa.text("ALTER TABLE function_target_events ADD COLUMN session_id VARCHAR(128)"))

    await conn_or_session.run_sync(_do_inspect)


async def create_tables() -> None:
    import app.models  # Ensure all model tables are registered on Base.metadata
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await safe_migrate(conn)

