"""Four-stage content security gates and Fail-Closed interception engine.

Compliant with:
- GB/T 45654 (Explicit AI content watermark & labeling)
- ISO/IEC 42001 & ISO/IEC 27001 (Security and AI risk management)
- Fail-Closed principle: Any anomaly or failure in security gate checks strictly
  denies access rather than failing open.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple

AI_WATERMARK_HEADER = "[AI生成内容标识: 由出海易审安全中台研判]"


@dataclass
class GateResult:
    """Standardized result returned by all security gates."""

    passed: bool
    reason: Optional[str] = None
    degraded: bool = False
    sanitized_content: Optional[Any] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class FailClosedException(Exception):
    """Exception raised when Fail-Closed interception is triggered."""

    def __init__(
        self,
        message: str = "内容安全合规网关不可用，根据 Fail-Closed 准则系统已主动熔断拦截该请求",
        code: int = 503,
        status: str = "security_service_unavailable",
        degraded: bool = True,
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status
        self.degraded = degraded
        self.timestamp = int(time.time())

    def to_response_dict(self) -> Dict[str, Any]:
        """Convert exception details to standardized JSON response structure."""
        return {
            "code": self.code,
            "status": self.status,
            "message": self.message,
            "degraded": self.degraded,
            "timestamp": self.timestamp,
        }


def run_with_fail_closed(
    fn: Callable[..., Any],
    *args: Any,
    raise_exception: bool = False,
    **kwargs: Any,
) -> GateResult:
    """Execute a security function under strict Fail-Closed semantics.

    If the target function encounters an unhandled exception or service error,
    it strictly blocks the operation, returning degraded=True and passed=False.
    """
    try:
        res = fn(*args, **kwargs)
        if isinstance(res, GateResult):
            return res
        return GateResult(passed=True, sanitized_content=res)
    except Exception as exc:
        if raise_exception:
            raise FailClosedException(
                message=f"内容安全合规网关不可用，根据 Fail-Closed 准则系统已主动熔断拦截该请求: {str(exc)}",
                code=503,
                status="security_service_unavailable",
                degraded=True,
            ) from exc
        return GateResult(
            passed=False,
            degraded=True,
            reason=f"Fail-Closed security interception triggered: {str(exc)}",
        )


# =====================================================================
# 闸门①: FileSecurityGate (Magic numbers, MIME, Disguise, Size)
# =====================================================================
class FileSecurityGate:
    """Gate ①: File Magic Number, MIME, Disguise, and Size Limit Verification."""

    DISALLOWED_EXTENSIONS = {
        ".exe", ".sh", ".bat", ".cmd", ".py", ".elf", ".bin",
        ".msi", ".dll", ".scr", ".vbs", ".js", ".jar", ".com"
    }

    ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".pdf", ".webp"}

    # Executable signatures that indicate binary disguise
    EXECUTABLE_SIGNATURES = [
        (b"MZ", "DOS/PE Executable (MZ header)"),
        (b"\x7fELF", "Linux ELF Binary header"),
        (b"#!\x2f", "UNIX Shell Shebang script"),
        (b"#!/", "UNIX Shell Shebang script"),
        (b"\xfe\xed\xfa\xce", "Mach-O Binary (32-bit)"),
        (b"\xfe\xed\xfa\xcf", "Mach-O Binary (64-bit)"),
        (b"\xce\xfa\xed\xfe", "Mach-O Binary (reverse)"),
        (b"\xcf\xfa\xed\xfe", "Mach-O Binary (reverse 64)"),
        (b"\xca\xfe\xba\xbe", "Java Bytecode / Mach-O Universal"),
    ]

    def __init__(self, max_size_mb: float = 10.0):
        self.max_size_bytes = int(max_size_mb * 1024 * 1024)

    def check(self, file_bytes: bytes, filename: str) -> GateResult:
        """Verify the integrity, type, and safety of an uploaded file."""
        if not file_bytes:
            return GateResult(passed=False, reason="File content is empty")

        if len(file_bytes) > self.max_size_bytes:
            return GateResult(
                passed=False,
                reason=f"File size exceeds limit ({len(file_bytes)} > {self.max_size_bytes} bytes)",
            )

        _, ext = os.path.splitext(filename.lower())

        # Check explicitly prohibited extensions
        if ext in self.DISALLOWED_EXTENSIONS:
            return GateResult(
                passed=False,
                reason=f"Disallowed executable or script extension: '{ext}'",
            )

        # Check executable binary disguises regardless of extension
        for sig, description in self.EXECUTABLE_SIGNATURES:
            if file_bytes.startswith(sig):
                return GateResult(
                    passed=False,
                    reason=f"Malicious executable disguise detected: {description}",
                )

        if ext not in self.ALLOWED_EXTENSIONS:
            return GateResult(
                passed=False,
                reason=f"File extension '{ext}' not in allowed set (PNG, JPEG, PDF, WEBP)",
            )

        # Validate Magic Numbers for allowed formats
        is_valid_format = False
        detected_mime = "application/octet-stream"

        if ext == ".png" and file_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
            is_valid_format = True
            detected_mime = "image/png"
        elif ext in {".jpg", ".jpeg"} and file_bytes.startswith(b"\xff\xd8\xff"):
            is_valid_format = True
            detected_mime = "image/jpeg"
        elif ext == ".pdf" and file_bytes.startswith(b"%PDF"):
            is_valid_format = True
            detected_mime = "application/pdf"
        elif ext == ".webp" and len(file_bytes) >= 12 and file_bytes.startswith(b"RIFF") and file_bytes[8:12] == b"WEBP":
            is_valid_format = True
            detected_mime = "image/webp"

        if not is_valid_format:
            return GateResult(
                passed=False,
                reason=f"File magic number header mismatch for extension '{ext}'",
            )

        return GateResult(
            passed=True,
            sanitized_content=file_bytes,
            metadata={"mime": detected_mime, "filename": filename, "size": len(file_bytes)},
        )


# =====================================================================
# 闸门②: TextBlacklistGate (Sensitive, Contraband, Code Injection)
# =====================================================================
class TextBlacklistGate:
    """Gate ②: Text Blacklist & Code/SQL Injection Detection."""

    DEFAULT_CONTRABAND_TERMS = [
        "枪支", "弹药", "假钞", "毒品", "违禁药物", "管制刀具",
        "炸药", "走私", "贩毒", "伪造证件", "涉赌", "颠覆政权",
        "分裂国家", "暴恐", "邪教"
    ]

    SCRIPT_PATTERNS = [
        re.compile(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL),
        re.compile(r"<\s*script[^>]*>", re.IGNORECASE),
        re.compile(r"javascript\s*:", re.IGNORECASE),
        re.compile(r"on(load|error|click|mouseover|submit)\s*=", re.IGNORECASE),
        re.compile(r"<\s*iframe[^>]*>", re.IGNORECASE),
    ]

    SQL_PATTERNS = [
        re.compile(r"(;\s*drop\s+table\b)", re.IGNORECASE),
        re.compile(r"(\bunion\s+(all\s+)?select\b)", re.IGNORECASE),
        re.compile(r"(\bdelete\s+from\b)", re.IGNORECASE),
        re.compile(r"(\binsert\s+into\b)", re.IGNORECASE),
        re.compile(r"(\bupdate\s+\w+\s+set\b)", re.IGNORECASE),
        re.compile(r"(--\s*$|/\*.*?\*/)", re.DOTALL),
    ]

    def __init__(self, additional_terms: Optional[list[str]] = None):
        self.prohibited_terms = list(self.DEFAULT_CONTRABAND_TERMS)
        if additional_terms:
            self.prohibited_terms.extend(additional_terms)

    def check(self, text: str) -> GateResult:
        """Inspect text for sensitive words, contraband, and injection attacks."""
        if not text:
            return GateResult(passed=True, sanitized_content="")

        # 1. Prohibited contraband & sensitive vocabulary
        for term in self.prohibited_terms:
            if term in text:
                return GateResult(
                    passed=False,
                    reason=f"Prohibited sensitive contraband keyword detected: '{term}'",
                )

        # 2. XSS and HTML Script injection
        for pattern in self.SCRIPT_PATTERNS:
            if pattern.search(text):
                return GateResult(
                    passed=False,
                    reason="Malicious HTML/JavaScript script injection detected",
                )

        # 3. SQL injection pattern
        for pattern in self.SQL_PATTERNS:
            if pattern.search(text):
                return GateResult(
                    passed=False,
                    reason="Malicious SQL statement injection pattern detected",
                )

        return GateResult(passed=True, sanitized_content=text)


# =====================================================================
# 闸门③: PromptInjectionGate (LLM Jailbreak & Tag Isolation)
# =====================================================================
class PromptInjectionGate:
    """Gate ③: LLM Prompt Injection Defense and Untrusted Input Wrapping."""

    JAILBREAK_PATTERNS = [
        re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
        re.compile(r"disregard\s+(all\s+)?prior\s+directives", re.IGNORECASE),
        re.compile(r"system\s*override", re.IGNORECASE),
        re.compile(r"system\s*prompt\s*override", re.IGNORECASE),
        re.compile(r"\bdan\s+mode\b", re.IGNORECASE),
        re.compile(r"do\s+anything\s+now", re.IGNORECASE),
        re.compile(r"\bjailbreak\b", re.IGNORECASE),
        re.compile(r"repeat\s+your\s+exact\s+system\s+prompt", re.IGNORECASE),
        re.compile(r"reveal\s+your\s+instructions", re.IGNORECASE),
        re.compile(r"output\s+your\s+system\s+prompt", re.IGNORECASE),
    ]

    @staticmethod
    def wrap_untrusted_input(content: str) -> str:
        """Encapsulate untrusted input within unambiguous structural boundary tags."""
        return f"<user_untrusted_input>\n{content}\n</user_untrusted_input>"

    def check(self, prompt: str) -> GateResult:
        """Detect jailbreak attempts and wrap safe input with strict isolation tags."""
        if not prompt:
            return GateResult(
                passed=True,
                sanitized_content=self.wrap_untrusted_input(""),
            )

        for pattern in self.JAILBREAK_PATTERNS:
            if pattern.search(prompt):
                return GateResult(
                    passed=False,
                    reason="LLM prompt injection or jailbreak attempt intercepted",
                )

        wrapped = self.wrap_untrusted_input(prompt)
        return GateResult(passed=True, sanitized_content=wrapped)


# =====================================================================
# 闸门④: OutputComplianceGate (Double Check & GB/T 45654 Watermark)
# =====================================================================
class OutputComplianceGate:
    """Gate ④: Output Double Check & Mandatory GB/T 45654 AI Watermark Injection."""

    SECRET_LEAK_PATTERNS = [
        re.compile(r"\bsk-[a-zA-Z0-9_-]{20,}\b"),
        re.compile(r"(?i)\b(api_key|secret_key|private_key)\s*[:=]\s*['\"][a-zA-Z0-9_-]{16,}['\"]"),
        re.compile(r"(?i)system\s+prompt:\s*<system_instructions>"),
    ]

    def check(self, llm_output: str, metadata: Optional[Dict[str, Any]] = None) -> GateResult:
        """Inspect LLM output for secret leaks and inject mandatory GB/T 45654 watermark."""
        if not llm_output:
            return GateResult(
                passed=True,
                sanitized_content=f"{AI_WATERMARK_HEADER}\n",
            )

        # Check for credential or internal system prompt leakage
        for pattern in self.SECRET_LEAK_PATTERNS:
            if pattern.search(llm_output):
                return GateResult(
                    passed=False,
                    reason="Internal credential or system prompt leakage detected in output",
                )

        # Inject GB/T 45654 watermark if not present
        sanitized = llm_output
        if AI_WATERMARK_HEADER not in sanitized:
            sanitized = f"{AI_WATERMARK_HEADER}\n{sanitized}"

        return GateResult(
            passed=True,
            sanitized_content=sanitized,
            metadata=metadata or {},
        )
