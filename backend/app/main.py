from __future__ import annotations
import asyncio
from contextlib import asynccontextmanager
import logging
import os
import sys
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.db import AsyncSessionLocal, async_engine, create_tables
from app.routers import (
    actions,
    attackers,
    audit,
    blocks,
    events,
    exposure,
    health,
    health_correlation,
    incidents,
    ioc,
    metrics,
    prediction,
    reports,
    simulate,
    whatif,
    ws,
    function_intelligence,
    gateway,
    failure_intelligence,
    git_intelligence,
    pagerduty,
    gateways,
    advisory,
    gateway_endpoints,
    assistant,
)
from app.demo_apps.real_app import router as real_app_router
from app.demo_apps.decoy_app import router as decoy_app_router
from app.services.enforcer import rollback_expired_blocks
from app.services.seed import seed_if_needed

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinel.soc")

_rollback_worker_task: asyncio.Task | None = None


async def _rollback_loop() -> None:
    logger.info("Starting background block rollback worker (interval=5s)...")
    while True:
        try:
            await asyncio.sleep(5)
            async with AsyncSessionLocal() as db:
                async with db.begin():
                    rolled = await rollback_expired_blocks(db)
                    if rolled > 0:
                        logger.info(f"Auto-rollback complete: released {rolled} expired block(s)")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in rollback loop: {e}", exc_info=False)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _rollback_worker_task

    # 1. Initialize DB schema
    await create_tables()
    logger.info("Database schema initialized.")

    # 2. Seed demo dataset if enabled
    async with AsyncSessionLocal() as db:
        async with db.begin():
            if settings.seed_demo:
                await seed_if_needed(db)
            else:
                from app.services.seed import seed_gateways_if_needed
                await seed_gateways_if_needed(db)
    logger.info("Demo attacker profiles and gateways verified successfully.")

    # 3. Start auto rollback worker
    _rollback_worker_task = asyncio.create_task(_rollback_loop())

    yield

    # Teardown
    if _rollback_worker_task:
        _rollback_worker_task.cancel()
        try:
            await _rollback_worker_task
        except asyncio.CancelledError:
            pass

    await async_engine.dispose()
    logger.info("SENTINEL SOC backend shutdown complete.")


app = FastAPI(
    title="SENTINEL SOC API",
    description="Deception-Driven Threat Detection & Automated Response Engine",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS setup - supports localhost, 127.0.0.1, and all LAN Wi-Fi subnets (10.x, 192.168.x, 172.16-31.x)
allowed_origins = [
    settings.frontend_origin,
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(events.router, prefix="/api", tags=["Events"])
app.include_router(attackers.router, prefix="/api", tags=["Attackers"])
app.include_router(incidents.router, prefix="/api", tags=["Incidents"])
app.include_router(actions.router, prefix="/api", tags=["Actions"])
app.include_router(blocks.router, prefix="/api", tags=["Blocks"])
app.include_router(metrics.router, prefix="/api", tags=["Metrics"])
app.include_router(health.router, prefix="/api", tags=["Health & Overview"])
app.include_router(reports.router, prefix="/api", tags=["Reports"])
app.include_router(ioc.router, prefix="/api", tags=["IOC"])
app.include_router(audit.router, prefix="/api", tags=["Audit & Integrity"])
app.include_router(whatif.router, prefix="/api", tags=["What-If Simulator"])
app.include_router(prediction.router, prefix="/api", tags=["Propagation Prediction"])
app.include_router(exposure.router, prefix="/api", tags=["Security Exposure Budget"])
app.include_router(health_correlation.router, prefix="/api", tags=["Health Correlation"])
app.include_router(function_intelligence.router, prefix="/api", tags=["Function Intelligence"])
app.include_router(gateway.router, prefix="/api", tags=["Gateway"])
app.include_router(gateway.router, tags=["Gateway Root"])
app.include_router(real_app_router)
app.include_router(decoy_app_router)
app.include_router(failure_intelligence.router, prefix="/api", tags=["Failure Intelligence"])
app.include_router(git_intelligence.router, prefix="/api", tags=["Git Intelligence"])
app.include_router(pagerduty.router, prefix="/api", tags=["PagerDuty Integration"])
app.include_router(gateways.router, prefix="/api", tags=["Gateway Lifecycle & Verification"])
app.include_router(advisory.router, prefix="/api", tags=["Remediation Advisor"])
app.include_router(assistant.router, prefix="/api", tags=["SOC Intelligent Assistant"])
app.include_router(gateway_endpoints.router, prefix="/api", tags=["Protected Gateways Traffic"])
app.include_router(gateway_endpoints.router, tags=["Protected Gateways Traffic Root"])
app.include_router(simulate.router, prefix="/api", tags=["Simulation"])
app.include_router(ws.router, tags=["WebSocket"])


@app.get("/health", tags=["Root"])
async def root_health():
    return {"status": "ok", "service": "SENTINEL SOC", "version": "1.0.0"}


@app.get("/", tags=["Root"])
async def root():
    return {
        "service": "SENTINEL SOC",
        "status": "operational",
        "docs": "/docs",
        "ws": "/ws/live",
    }

