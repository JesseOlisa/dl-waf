import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend import database, inference
from backend.middleware import WAFMiddleware
from backend.routes import auth, demo, events, simulation, staff, stats, waf

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    database.init_db()
    inference.load_model_and_vocab()
    yield


app = FastAPI(
    title="DL-WAF",
    description="Deep Learning Web Application Firewall",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow dashboard frontend (adjust origins for production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# WAF middleware — must be added AFTER CORS so it runs on every proxied request
app.add_middleware(WAFMiddleware)

# Dashboard API routes
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(stats.router, prefix="/api/stats", tags=["stats"])
app.include_router(events.router, prefix="/api/events", tags=["events"])
app.include_router(waf.router, prefix="/api/waf", tags=["waf"])
app.include_router(simulation.router, prefix="/api/sim", tags=["simulation"])
app.include_router(staff.router, prefix="/api/staff", tags=["staff"])

# Demo route — live presentation page
app.include_router(demo.router)


if __name__ == "__main__":
    from backend.config import settings

    uvicorn.run(
        "backend.main:app",
        host=settings.waf_host,
        port=settings.waf_port,
        reload=False,
        log_level="info",
    )
