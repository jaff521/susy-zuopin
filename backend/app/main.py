"""FastAPI Application Entry Point.

Mounts:
- Token Bucket Rate Limiting Middleware
- ISO 27001 & OWASP Recommended HTTP Security Headers
- CORS Middleware
- API Router (/api/v1)
- Automatic DB Schema Initialization
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import api_router
from app.config import get_settings
from app.db.session import init_db
from app.security.limiter import TokenBucketLimiter

logger = logging.getLogger("app.main")
settings = get_settings()

# Global Rate Limiter instance
limiter = TokenBucketLimiter(
    rate_per_minute=getattr(settings, "RATE_LIMIT_PER_MINUTE", 10),
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager to initialize DB tables."""
    init_db()
    yield


app = FastAPI(
    title="出海易审 · Cross-Border Compliance AI Safeguard Platform",
    description="Enterprise-grade AI compliance diagnostic, regulatory traceability, and risk gate platform.",
    version="1.0.0",
    lifespan=lifespan,
)

# -----------------------------------------------------------------------------
# CORS Middleware (OWASP Secure Configuration)
# -----------------------------------------------------------------------------
ALLOWED_ORIGINS = [
    "http://localhost",
    "http://localhost:80",
    "http://localhost:8000",
    "http://localhost:8080",
    "http://localhost:5173",
    "http://127.0.0.1",
    "http://127.0.0.1:80",
    "http://127.0.0.1:8000",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:5173",
    "http://8.130.79.175",
    "http://8.130.79.175:80",
    "http://8.130.79.175:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1|8\.130\.79\.175)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


# -----------------------------------------------------------------------------
# Rate Limiting Middleware (HTTP 429 Protection)
# -----------------------------------------------------------------------------
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Enforce token bucket rate limiting on heavy compliance creation endpoints."""
    path = request.url.path
    if path.startswith("/api/v1/compliance/tasks/create"):
        client_ip = (
            request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or (request.client.host if request.client else "127.0.0.1")
        )
        try:
            limiter.check_rate_limit(key=client_ip)
        except HTTPException as exc:
            return JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail},
                headers=exc.headers or {},
            )
    return await call_next(request)


# -----------------------------------------------------------------------------
# Security Headers Middleware
# -----------------------------------------------------------------------------
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Inject OWASP & ISO 27001 recommended secure HTTP headers into all responses."""
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


from pathlib import Path
from fastapi.staticfiles import StaticFiles

# Mount API Routes
app.include_router(api_router)


@app.get("/health", tags=["Health"])
def health_check():
    """System liveness and readiness probe."""
    return {
        "status": "ok",
        "service": "crossborder-safeguard-backend",
        "version": "1.0.0",
    }


# -----------------------------------------------------------------------------
# Single-Port Web Dashboard Static Hosting (Zero CORS)
# -----------------------------------------------------------------------------
static_dir = Path(__file__).resolve().parent.parent.parent / "static_web"
if static_dir.exists():
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static_web")
