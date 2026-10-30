"""Core Compliance Pipeline Engine orchestrating 9-stage end-to-end statutory review.

Full pipeline flow:
1. Gate ① (FileSecurityGate): File magic numbers, MIME, disguise & size check.
2. Local OCR Extraction (OCRService): Extract CE marks, EU REP, warnings, batch numbers.
3. Instant Physical Erasure: Overwrite and call os.unlink immediately to ensure zero residue.
4. Gate ② (TextBlacklistGate): Contraband, sensitive words, XSS & SQL injection filtering.
5. RAG Statutory Knowledge Retrieval (RAGService): Vector search for EU compliance directives.
6. Gate ③ (PromptInjectionGate): Detect jailbreak attempts & wrap safe input into isolation tags.
7. Aliyun Qwen LLM Analysis (LLMComplianceService): Legal judgment or deterministic offline replay.
8. Gate ④ (OutputComplianceGate): Dual-direction verification & GB/T 45654 AI watermark injection.
9. SQLite Tenant Persistence & Immutable Audit Log: Tenant-isolated storage and tamper-evident audit logging.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict, Optional, Tuple
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.db.models import AuditLog, ComplianceReport, ComplianceTask
from app.db.session import SessionLocal
from app.schemas.compliance import ComplianceReportSchema
from app.security.crypto import mask_sensitive_text
from app.security.gates import (
    FileSecurityGate,
    OutputComplianceGate,
    PromptInjectionGate,
    TextBlacklistGate,
)
from app.services.llm_service import LLMComplianceService
from app.services.ocr_service import OCRResult, OCRService
from app.services.rag_service import RAGService


class CompliancePipelineEngine:
    """Enterprise-grade orchestrator executing the 9-stage compliance review pipeline."""

    def __init__(
        self,
        file_gate: Optional[FileSecurityGate] = None,
        text_gate: Optional[TextBlacklistGate] = None,
        prompt_gate: Optional[PromptInjectionGate] = None,
        output_gate: Optional[OutputComplianceGate] = None,
        ocr_service: Optional[OCRService] = None,
        rag_service: Optional[RAGService] = None,
        llm_service: Optional[LLMComplianceService] = None,
    ):
        self.file_gate = file_gate or FileSecurityGate()
        self.text_gate = text_gate or TextBlacklistGate()
        self.prompt_gate = prompt_gate or PromptInjectionGate()
        self.output_gate = output_gate or OutputComplianceGate()
        self.ocr_service = ocr_service or OCRService()
        self.rag_service = rag_service or RAGService()
        self.llm_service = llm_service or LLMComplianceService(rag_service=self.rag_service)

    def run_pipeline(
        self,
        user_id: str,
        product_name: str,
        category: str,
        target_country: str = "EU",
        description: str = "",
        file_bytes: Optional[bytes] = None,
        filename: Optional[str] = None,
        db: Optional[Session] = None,
        ip_address: Optional[str] = None,
        offline_mode: Optional[bool] = None,
    ) -> Tuple[ComplianceTask, ComplianceReport, ComplianceReportSchema]:
        """Execute the full 9-stage compliance review pipeline."""
        own_db = False
        if db is None:
            db = SessionLocal()
            own_db = True

        try:
            # ---------------------------------------------------------
            # Stage 1: Gate ① - File Security Check
            # ---------------------------------------------------------
            if file_bytes is not None and len(file_bytes) > 0:
                gate1_res = self.file_gate.check(
                    file_bytes=file_bytes,
                    filename=filename or "material.png",
                )
                if not gate1_res.passed:
                    self._record_gate_failure(
                        db=db,
                        user_id=user_id,
                        action="GATE_1_FILE_SECURITY_INTERCEPTED",
                        ip_address=ip_address,
                        reason=gate1_res.reason or "File security gate failed",
                    )
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Gate 1 File Security Check Failed: {gate1_res.reason}",
                    )

            # ---------------------------------------------------------
            # Stage 2 & 3: Local OCR Extraction & Instant Physical Erasure
            # ---------------------------------------------------------
            ocr_res: OCRResult
            if file_bytes is not None and len(file_bytes) > 0:
                ext = os.path.splitext(filename or ".png")[1] or ".png"
                temp_fd, temp_path = tempfile.mkstemp(prefix="compliance_upload_", suffix=ext)
                try:
                    with os.fdopen(temp_fd, "wb") as f:
                        f.write(file_bytes)

                    ocr_res = self.ocr_service.extract_from_image(temp_path, filename=filename or "")
                finally:
                    # Stage 3: Immediate physical erasure - zero overwrite then unlink
                    if os.path.exists(temp_path):
                        try:
                            file_size = os.path.getsize(temp_path)
                            with open(temp_path, "wb") as f_wipe:
                                f_wipe.write(b"\x00" * file_size)
                        except Exception:
                            pass
                        os.unlink(temp_path)
            else:
                combined_input_text = f"{product_name}\n{description}".strip()
                ocr_res = self.ocr_service.extract_from_text(combined_input_text)

            # ---------------------------------------------------------
            # Stage 4: Gate ② - Text Blacklist & Contraband / Injection Check
            # ---------------------------------------------------------
            text_to_audit = f"{product_name} {category} {description} {ocr_res.raw_text}"
            gate2_res = self.text_gate.check(text_to_audit)
            if not gate2_res.passed:
                self._record_gate_failure(
                    db=db,
                    user_id=user_id,
                    action="GATE_2_TEXT_BLACKLIST_INTERCEPTED",
                    ip_address=ip_address,
                    reason=gate2_res.reason or "Text blacklist gate failed",
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Gate 2 Text Blacklist Check Failed: {gate2_res.reason}",
                )

            # ---------------------------------------------------------
            # Stage 5: RAG Statutory Knowledge Retrieval
            # ---------------------------------------------------------
            search_query = f"{product_name} {category} {ocr_res.raw_text}".strip()
            retrieved_regulations = self.rag_service.search_regulations(
                query=search_query,
                category=category,
                top_k=3,
            )

            # ---------------------------------------------------------
            # Stage 6: Gate ③ - Prompt Injection Defense & Tag Wrapping
            # ---------------------------------------------------------
            prompt_context = f"{product_name}\n{description}\n{ocr_res.raw_text}"
            gate3_res = self.prompt_gate.check(prompt_context)
            if not gate3_res.passed:
                self._record_gate_failure(
                    db=db,
                    user_id=user_id,
                    action="GATE_3_PROMPT_INJECTION_INTERCEPTED",
                    ip_address=ip_address,
                    reason=gate3_res.reason or "Prompt injection intercepted",
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Gate 3 Prompt Injection Check Failed: {gate3_res.reason}",
                )

            # ---------------------------------------------------------
            # Stage 7: Aliyun Qwen LLM Legal Analysis / Offline Replay
            # ---------------------------------------------------------
            is_offline = offline_mode if offline_mode is not None else True
            report_schema: ComplianceReportSchema = self.llm_service.diagnose_compliance(
                product_name=product_name,
                category=category,
                target_country=target_country,
                ocr_result=ocr_res,
                retrieved_regulations=retrieved_regulations,
                offline_mode=is_offline,
            )

            # ---------------------------------------------------------
            # Stage 8: Gate ④ - Output Compliance Check & GB/T 45654 Watermark
            # ---------------------------------------------------------
            gate4_res = self.output_gate.check(
                llm_output=report_schema.to_json(),
                metadata={"product_name": product_name},
            )
            if not gate4_res.passed:
                self._record_gate_failure(
                    db=db,
                    user_id=user_id,
                    action="GATE_4_OUTPUT_COMPLIANCE_INTERCEPTED",
                    ip_address=ip_address,
                    reason=gate4_res.reason or "Output compliance gate failed",
                )
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Gate 4 Output Compliance Check Failed: {gate4_res.reason}",
                )

            # ---------------------------------------------------------
            # Stage 9: SQLite Tenant Persistence & Immutable Audit Log
            # ---------------------------------------------------------
            task = ComplianceTask(
                user_id=user_id,
                product_name=product_name,
                category=category,
                target_country=target_country,
                status="COMPLETED",
            )
            db.add(task)
            db.flush()

            report_schema.task_id = task.id

            report = ComplianceReport(
                id=report_schema.report_id,
                task_id=task.id,
                user_id=user_id,
                overall_score=report_schema.score_overview.overall_score,
                risk_level=report_schema.score_overview.risk_level.value,
                report_json=report_schema.to_json(),
            )
            db.add(report)
            db.flush()

            audit_log = AuditLog(
                user_id=user_id,
                action="COMPLIANCE_REVIEW_COMPLETED",
                ip_address=ip_address or "127.0.0.1",
                detail_json=json.dumps(
                    {
                        "task_id": task.id,
                        "report_id": report.id,
                        "product_name": mask_sensitive_text(product_name),
                        "overall_score": report.overall_score,
                        "risk_level": report.risk_level,
                        "defects_count": len(report_schema.defects),
                    },
                    ensure_ascii=False,
                ),
            )
            db.add(audit_log)
            db.commit()
            db.refresh(task)
            db.refresh(report)

            return task, report, report_schema

        finally:
            if own_db:
                db.close()

    def _record_gate_failure(
        self,
        db: Session,
        user_id: str,
        action: str,
        ip_address: Optional[str],
        reason: str,
    ) -> None:
        """Record security gate interception to immutable audit logs."""
        try:
            audit = AuditLog(
                user_id=user_id,
                action=action,
                ip_address=ip_address or "127.0.0.1",
                detail_json=json.dumps({"reason": mask_sensitive_text(reason)}, ensure_ascii=False),
            )
            db.add(audit)
            db.commit()
        except Exception:
            db.rollback()
