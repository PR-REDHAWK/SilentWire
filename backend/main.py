import os
import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.database import init_db
from backend.websocket import ws_manager
from backend.api import alerts, flows, statistics, models, correlations

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("OracleShieldBackend")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing OracleShield Database...")
    await init_db()
    yield
    logger.info("Shutting down OracleShield Backend.")

app = FastAPI(
    title="OracleShield — Passive Threat Intelligence API",
    description="AI-Powered Threat Detection Platform for Unidirectional IP Traffic",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(alerts.router)
app.include_router(correlations.router)
app.include_router(flows.router)
app.include_router(statistics.router)
app.include_router(models.router)

@app.get("/api/health")
async def health_check():
    return {
        "status": "HEALTHY",
        "system": "OracleShield Passive Threat Engine",
        "mode": "READ_ONLY_UNIDIRECTIONAL",
        "active_response": False
    }

@app.websocket("/ws/alerts")
async def websocket_alerts_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)

# Serve dashboard static files if built
dashboard_dist = os.path.abspath("dashboard/dist")
if os.path.exists(dashboard_dist):
    app.mount("/", StaticFiles(directory=dashboard_dist, html=True), name="dashboard")
