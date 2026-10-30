"""CrossBorder SafeGuard Security Package.

Provides four-stage fail-closed content safety gates, token bucket rate limiter,
JWT authentication with IDOR prevention, and AES-256-GCM encryption utilities.
"""

from app.security.crypto import (
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    mask_sensitive_text,
)
from app.security.gates import (
    AI_WATERMARK_HEADER,
    FileSecurityGate,
    TextBlacklistGate,
    PromptInjectionGate,
    OutputComplianceGate,
    GateResult,
    FailClosedException,
    run_with_fail_closed,
)
from app.security.limiter import TokenBucketLimiter
from app.security.auth import (
    get_password_hash,
    verify_password,
    create_access_token,
    decode_access_token,
    get_current_user,
    verify_tenant_access,
)

__all__ = [
    "encrypt_aes_gcm",
    "decrypt_aes_gcm",
    "mask_sensitive_text",
    "AI_WATERMARK_HEADER",
    "FileSecurityGate",
    "TextBlacklistGate",
    "PromptInjectionGate",
    "OutputComplianceGate",
    "GateResult",
    "FailClosedException",
    "run_with_fail_closed",
    "TokenBucketLimiter",
    "get_password_hash",
    "verify_password",
    "create_access_token",
    "decode_access_token",
    "get_current_user",
    "verify_tenant_access",
]
