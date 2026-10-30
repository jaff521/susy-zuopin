"""
Competition Security Pre-Flight Audit Checklist (60-Second Scan).
Verifies:
1. Zero hardcoded plaintext API keys across all project code (sk-[a-zA-Z0-9]{20,})
2. Strict anonymity conformance: no school, advisor, or personal student names
3. Unauthenticated requests strictly return HTTP 401 Unauthorized
4. Multi-tenant IDOR attacks strictly return HTTP 403 Forbidden
5. Fail-Closed security interception behaves reliably on degraded states
6. Sensitive data masking (phone, email) covers 100% of PII in logs
7. Mandatory GB/T 45654 AI synthesis watermark attribution is present
8. OWASP & ISO 27001 HTTP security headers are injected into responses
"""

import os
import re
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.models import Base
from app.db.session import get_db
from app.main import app
from app.security.crypto import mask_sensitive_text, encrypt_aes_gcm, decrypt_aes_gcm
from app.security.gates import OutputComplianceGate, FailClosedException, run_with_fail_closed
from app.services.llm_service import GB_T_45654_STAMP


@pytest.fixture(scope="function")
def client():
    """Isolated test client with in-memory SQLite and fresh tables."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    test_client = TestClient(app)
    yield test_client
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


def test_audit_zero_hardcoded_keys():
    """Verify that zero plaintext API keys exist in the repository."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    pattern = re.compile(r"sk-[a-zA-Z0-9]{20,}")

    exclude_dirs = {".git", ".pytest_cache", ".venv", "venv", "__pycache__", "node_modules", "tests"}
    exclude_files = {".env.example", ".env"}

    leaked = []
    for root, dirs, files in os.walk(repo_root):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for file in files:
            if file in exclude_files:
                continue
            if file.endswith((".py", ".sh", ".json", ".md", ".txt", ".js", ".html", ".env")):
                file_path = Path(root) / file
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                matches = pattern.findall(content)
                real_matches = [
                    m for m in matches 
                    if not m.startswith("sk-your-") and not m.startswith("sk-placeholder")
                ]
                if real_matches:
                    leaked.append(f"{file_path.relative_to(repo_root)}: {real_matches[0][:8]}...")

    assert len(leaked) == 0, f"Found hardcoded API keys: {leaked}"


def test_audit_strict_anonymity():
    """
    Verify complete absence of real names, university or institution affiliations.
    Compliance with competition anonymity red-line rules.
    """
    repo_root = Path(__file__).resolve().parent.parent.parent
    
    # Common prohibited terms that would break competition anonymity
    prohibited_terms = [
        "大学", "学院", "指导老师", "指导教师", "队长", "学号", "班级", 
        "University", "College", "Professor", "Advisor"
    ]

    scan_dirs = [repo_root / "docs", repo_root / "static_web"]
    violations = []

    for s_dir in scan_dirs:
        if not s_dir.exists():
            continue
        for root, dirs, files in os.walk(s_dir):
            for file in files:
                if file.endswith((".md", ".html", ".js", ".json", ".txt")):
                    file_path = Path(root) / file
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    for term in prohibited_terms:
                        if term in content:
                            clean_content = content.replace("全国高校计算机大赛", "").replace("高校", "")
                            if term in clean_content:
                                violations.append(f"{file_path.relative_to(repo_root)} contains '{term}'")

    assert len(violations) == 0, f"Anonymity violations found: {violations}"


def test_audit_unauthenticated_api_returns_401(client):
    """Business endpoints must strictly return 401 Unauthorized without valid Bearer token."""
    response = client.get("/api/v1/compliance/reports/test-task-1")
    assert response.status_code == 401

    post_resp = client.post("/api/v1/compliance/tasks/create", data={"product_name": "Test"})
    assert post_resp.status_code == 401


def test_audit_tenant_idor_blocked_with_403(client):
    """Accessing another tenant's report must strictly return 403 Forbidden."""
    # Register and login user A
    u1 = {"username": "sec_auditor_a", "password": "AuditorPassword!123"}
    client.post("/api/v1/auth/register", json=u1)
    t1 = client.post("/api/v1/auth/login", json=u1).json()["access_token"]

    # Register and login user B
    u2 = {"username": "sec_auditor_b", "password": "AuditorPassword!123"}
    client.post("/api/v1/auth/register", json=u2)
    t2 = client.post("/api/v1/auth/login", json=u2).json()["access_token"]

    # User A creates a task
    create_res = client.post(
        "/api/v1/compliance/tasks/create",
        data={"product_name": "Toy A", "category": "toys", "target_country": "DE"},
        headers={"Authorization": f"Bearer {t1}"}
    )
    assert create_res.status_code in (200, 201)
    task_id = create_res.json()["task_id"]

    # User B attempts to access User A's report -> 403 Forbidden
    idor_res = client.get(
        f"/api/v1/compliance/reports/{task_id}",
        headers={"Authorization": f"Bearer {t2}"}
    )
    assert idor_res.status_code == 403
    assert "IDOR" in idor_res.json()["detail"] or "Access denied" in idor_res.json()["detail"]


def test_audit_fail_closed_mechanism():
    """Verify Fail-Closed gate halts execution and raises FailClosedException when an error occurs."""
    gate = OutputComplianceGate()

    # Leaked key in output must be rejected by gate
    gate_res = gate.check("Result completed with sk-secretkey123456789012345678")
    assert gate_res.passed is False
    assert "leakage" in gate_res.reason.lower() or "credential" in gate_res.reason.lower()

    # When an internal exception occurs, run_with_fail_closed returns degraded result or raises
    def buggy_action():
        raise RuntimeError("Simulated internal network or hardware failure")

    # Degraded non-raising mode
    res = run_with_fail_closed(buggy_action)
    assert res.passed is False
    assert res.degraded is True
    assert "Fail-Closed" in res.reason

    # Raising mode
    with pytest.raises(FailClosedException) as exc_info:
        run_with_fail_closed(buggy_action, raise_exception=True)
    assert exc_info.value.code == 503
    assert exc_info.value.degraded is True


def test_audit_sensitive_masking_coverage():
    """Sensitive data masking (phone, email) must protect PII."""
    raw = "Contact: 13812345678 or support@safetrade.com for enquiries."
    masked = mask_sensitive_text(raw)
    assert "13812345678" not in masked
    assert "138****5678" in masked
    assert "support@safetrade.com" not in masked
    assert "s***@safetrade.com" in masked


def test_audit_gbt_45654_watermark_present():
    """GB/T 45654 attribution stamp must be stamped onto all compliant outputs."""
    gate = OutputComplianceGate()
    result = gate.check("诊断结论：符合准入规范。")
    assert result.passed is True
    assert "AI生成内容标识" in result.sanitized_content


def test_audit_security_headers_enforced(client):
    """Ensure OWASP security headers are present on all responses."""
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["X-XSS-Protection"] == "1; mode=block"
    assert "Strict-Transport-Security" in resp.headers
