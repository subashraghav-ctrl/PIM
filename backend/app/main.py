from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.api.v1.router import api_router
from app.admin.router import router as admin_router
from app.scheduler.jobs import start_scheduler, stop_scheduler

logging.basicConfig(level=logging.INFO if not settings.DEBUG else logging.DEBUG)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    start_scheduler()
    logger.info("PIM application started")
    yield
    stop_scheduler()
    logger.info("PIM application stopped")


app = FastAPI(
    title="Privilege Identity Management (PIM)",
    description="Manage privileged access with RBAC, JIT elevation, approval workflows, and audit logging.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)
app.include_router(admin_router)


@app.get("/health", tags=["health"])
def health_check():
    return {"status": "ok", "service": "PIM"}
