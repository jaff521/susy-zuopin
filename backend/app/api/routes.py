"""FastAPI RESTful API route definitions for authentication and compliance review.

Endpoints:
- POST /api/v1/auth/register : Merchant self-service registration
- POST /api/v1/auth/login    : Standard JWT credential authentication
- POST /api/v1/auth/token    : OAuth2 compatible token grant
- POST /api/v1/compliance/tasks/create : End-to-end 9-stage compliance review
- GET  /api/v1/compliance/reports/{id} : Report detail with IDOR tenant protection
- GET  /api/v1/compliance/reports/{id}/export-pdf : Export standard PDF report
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.models import ComplianceReport, ComplianceTask, User
from app.db.session import get_db
from app.pipeline.engine import CompliancePipelineEngine
from app.security.auth import (
    create_access_token,
    get_current_user,
    get_password_hash,
    verify_password,
    verify_tenant_access,
)
from app.services.pdf_service import PDFService

api_router = APIRouter(prefix="/api/v1")
auth_router = APIRouter(prefix="/auth", tags=["Authentication"])
compliance_router = APIRouter(prefix="/compliance", tags=["Compliance"])

# Global pipeline and PDF service singletons
pipeline_engine = CompliancePipelineEngine()
pdf_service = PDFService()


# -----------------------------------------------------------------------------
# Auth Schemas
# -----------------------------------------------------------------------------
class UserAuthRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=6, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: str
    username: str


# -----------------------------------------------------------------------------
# Auth Endpoints
# -----------------------------------------------------------------------------
@auth_router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(req: UserAuthRequest, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Register a new tenant/merchant account."""
    existing = db.query(User).filter(User.username == req.username).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered. Please choose another username.",
        )

    hashed_pw = get_password_hash(req.password)
    user = User(username=req.username, hashed_password=hashed_pw)
    db.add(user)
    db.commit()
    db.refresh(user)

    return {"id": user.id, "username": user.username}


@auth_router.post("/login", response_model=TokenResponse)
def login(req: UserAuthRequest, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Authenticate merchant credentials and issue a signed JWT access token."""
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token({"sub": str(user.id), "username": user.username})
    return {"access_token": token, "token_type": "bearer"}


@auth_router.post("/token", response_model=TokenResponse)
def oauth2_login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)) -> Dict[str, Any]:
    """OAuth2 password grant endpoint for Swagger UI & automated tools."""
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token({"sub": str(user.id), "username": user.username})
    return {"access_token": token, "token_type": "bearer"}


# -----------------------------------------------------------------------------
# Compliance Endpoints
# -----------------------------------------------------------------------------
@compliance_router.post("/tasks/create", status_code=status.HTTP_201_CREATED)
async def create_compliance_task(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Upload material image or submit text parameters to run 9-stage compliance review."""
    content_type = request.headers.get("content-type", "")

    file_bytes: Optional[bytes] = None
    filename: Optional[str] = None
    product_name: str = ""
    category: str = "toys"
    target_country: str = "EU"
    settings = get_settings()
    has_api_key = bool(getattr(settings, "DASHSCOPE_API_KEY", ""))
    default_offline = False if has_api_key else True
    offline_mode: bool = default_offline

    if "application/json" in content_type:
        body = await request.json()
        product_name = body.get("product_name", "")
        category = body.get("category", "toys")
        target_country = body.get("target_country", "EU")
        description = body.get("description", "")
        if "offline_mode" in body:
            offline_mode = bool(body.get("offline_mode"))
        else:
            offline_mode = default_offline
    else:
        form = await request.form()
        product_name = str(form.get("product_name", ""))
        category = str(form.get("category", "toys"))
        target_country = str(form.get("target_country", "EU"))
        description = str(form.get("description", ""))
        raw_offline = form.get("offline_mode")
        if raw_offline is not None:
            offline_mode = str(raw_offline).lower() in ("true", "1", "yes")
        else:
            offline_mode = default_offline

        file_field = form.get("file")
        if file_field and hasattr(file_field, "read"):
            file_bytes = await file_field.read()
            filename = getattr(file_field, "filename", "material.png")

    if not product_name.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Field 'product_name' cannot be empty.",
        )

    client_ip = (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or (request.client.host if request.client else "127.0.0.1")
    )

    task, report, report_schema = pipeline_engine.run_pipeline(
        user_id=str(current_user.id),
        product_name=product_name,
        category=category,
        target_country=target_country,
        description=description,
        file_bytes=file_bytes,
        filename=filename,
        db=db,
        ip_address=client_ip,
        offline_mode=offline_mode,
    )

    return {
        "task_id": task.id,
        "report_id": report.id,
        "status": task.status,
        "product_name": task.product_name,
        "overall_score": report.overall_score,
        "risk_level": report.risk_level,
        "report": json.loads(report.report_json),
        "message": "Compliance review completed successfully",
    }


@compliance_router.get("/reports/{report_id}")
def get_compliance_report(
    report_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Retrieve compliance diagnostic report with tenant IDOR protection."""
    report = (
        db.query(ComplianceReport)
        .filter(
            (ComplianceReport.id == report_id) | (ComplianceReport.task_id == report_id)
        )
        .first()
    )

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Compliance report '{report_id}' not found.",
        )

    # Strictly enforce row-level tenant boundary (prevent IDOR)
    verify_tenant_access(resource_user_id=report.user_id, current_user=current_user)

    return {
        "report_id": report.id,
        "task_id": report.task_id,
        "user_id": report.user_id,
        "overall_score": report.overall_score,
        "risk_level": report.risk_level,
        "report": json.loads(report.report_json),
        "created_at": report.created_at.isoformat(),
    }


@compliance_router.get("/reports/{report_id}/export-pdf")
def export_report_pdf(
    report_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    """Export compliance diagnosis as a formatted PDF with tenant IDOR protection."""
    report = (
        db.query(ComplianceReport)
        .filter(
            (ComplianceReport.id == report_id) | (ComplianceReport.task_id == report_id)
        )
        .first()
    )

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Compliance report '{report_id}' not found.",
        )

    # Strictly enforce row-level tenant boundary
    verify_tenant_access(resource_user_id=report.user_id, current_user=current_user)

    task = db.query(ComplianceTask).filter(ComplianceTask.id == report.task_id).first()
    pdf_bytes = pdf_service.generate_report_pdf(report_data=report, task=task)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="compliance_report_{report.id}.pdf"',
            "Content-Type": "application/pdf",
        },
    )


# Mount sub-routers to main api_router
api_router.include_router(auth_router)
api_router.include_router(compliance_router)
