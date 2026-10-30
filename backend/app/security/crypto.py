import base64
import os
import re
from typing import Optional, Union
from Crypto.Cipher import AES

from app.config import get_settings


def _normalize_key(key: Optional[Union[str, bytes]]) -> bytes:
    """Normalize input key to exactly 32 bytes (256 bits)."""
    if key is None:
        key = get_settings().AES_SECRET_KEY

    if isinstance(key, str):
        # If hex string with 64 chars
        if len(key) == 64:
            try:
                key_bytes = bytes.fromhex(key)
                if len(key_bytes) == 32:
                    return key_bytes
            except ValueError:
                pass
        key_bytes = key.encode("utf-8")
    else:
        key_bytes = key

    if len(key_bytes) != 32:
        raise ValueError(
            f"AES-256 requires a 256-bit (32-byte) key, got {len(key_bytes)} bytes."
        )
    return key_bytes


def encrypt_aes_gcm(plaintext: str, key: Optional[Union[str, bytes]] = None) -> str:
    """Encrypt a plaintext string using AES-256-GCM.
    
    Returns a URL-safe or standard Base64 string containing:
    nonce (12 bytes) + tag (16 bytes) + ciphertext.
    """
    key_bytes = _normalize_key(key)
    cipher = AES.new(key_bytes, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    # cipher.nonce is 16 bytes by default in PyCryptodome, or 12-16 bytes
    nonce = cipher.nonce
    nonce_len = len(nonce).to_bytes(1, byteorder="big")
    payload = nonce_len + nonce + tag + ciphertext
    return base64.b64encode(payload).decode("utf-8")


def decrypt_aes_gcm(ciphertext_b64: str, key: Optional[Union[str, bytes]] = None) -> str:
    """Decrypt and verify an AES-256-GCM encrypted base64 payload.
    
    Raises ValueError or KeyError if decryption/tag verification fails.
    """
    key_bytes = _normalize_key(key)
    try:
        payload = base64.b64decode(ciphertext_b64.encode("utf-8"))
        nonce_len = payload[0]
        nonce = payload[1 : 1 + nonce_len]
        tag = payload[1 + nonce_len : 1 + nonce_len + 16]
        ciphertext = payload[1 + nonce_len + 16 :]

        cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
        plaintext_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext_bytes.decode("utf-8")
    except Exception as e:
        raise ValueError(f"Decryption failed or data integrity check failed: {str(e)}") from e


_PHONE_PATTERN = re.compile(r"(?<!\d)(1[3-9]\d)(\d{4})(\d{4})(?!\d)")
_EMAIL_PATTERN = re.compile(
    r"\b([a-zA-Z0-9_.+-])[a-zA-Z0-9_.+-]*@([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)\b"
)


def mask_sensitive_text(text: Optional[str]) -> str:
    """Mask phone numbers and email addresses in logs and reports for privacy compliance.
    
    - Phone: 13812345678 -> 138****5678
    - Email: admin@domain.com -> a***@domain.com
    """
    if not text:
        return "" if text is not None else None

    # Mask Chinese standard phone numbers
    masked = _PHONE_PATTERN.sub(r"\1****\3", text)
    # Mask Email addresses
    masked = _EMAIL_PATTERN.sub(r"\1***@\2", masked)
    return masked
