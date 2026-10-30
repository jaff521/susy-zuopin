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
# CORS Middleware
# -----------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
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
