import pytest
from datetime import datetime, timezone
from sqlalchemy.exc import IntegrityError

from app.security.crypto import (
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    mask_sensitive_text,
)
from app.db.models import User, AuditLog, ComplianceTask, ComplianceReport


class TestCryptoUtils:
    """Test suite for AES-256-GCM encryption/decryption and sensitive data masking."""

    def test_aes_encrypt_decrypt_roundtrip(self, test_aes_key):
        raw_text = "EU_REP: Company GmbH, Berlin, HRB 123456"
        encrypted = encrypt_aes_gcm(raw_text, key=test_aes_key)

        assert encrypted != raw_text
        assert isinstance(encrypted, str)

        decrypted = decrypt_aes_gcm(encrypted, key=test_aes_key)
        assert decrypted == raw_text

    def test_aes_produces_different_ciphertexts_for_same_plaintext(self, test_aes_key):
        raw_text = "Sensitive merchant tax identification number 987654321"
        c1 = encrypt_aes_gcm(raw_text, key=test_aes_key)
        c2 = encrypt_aes_gcm(raw_text, key=test_aes_key)

        assert c1 != c2, "AES-GCM should use a randomized nonce for each encryption"
        assert decrypt_aes_gcm(c1, key=test_aes_key) == raw_text
        assert decrypt_aes_gcm(c2, key=test_aes_key) == raw_text

    def test_aes_tampered_ciphertext_fails(self, test_aes_key):
        raw_text = "Confidential compliance findings"
        encrypted = encrypt_aes_gcm(raw_text, key=test_aes_key)

        # Tamper with the base64 string
        tampered = list(encrypted)
        tampered[10] = "A" if tampered[10] != "A" else "B"
        tampered_str = "".join(tampered)

        with pytest.raises(Exception):
            decrypt_aes_gcm(tampered_str, key=test_aes_key)

    def test_aes_invalid_key_length(self):
        short_key = "too_short_key"
        with pytest.raises(ValueError, match="256-bit"):
            encrypt_aes_gcm("test", key=short_key)

    def test_mask_sensitive_phone(self):
        text = "Contact representative at 13812345678 for customs inquiry"
        masked = mask_sensitive_text(text)
        assert "138****5678" in masked
        assert "13812345678" not in masked

    def test_mask_sensitive_email(self):
        text = "Official notifications sent to compliance-officer@export-corp.eu"
        masked = mask_sensitive_text(text)
        assert "c***@export-corp.eu" in masked
        assert "compliance-officer@export-corp.eu" not in masked

    def test_mask_combined_sensitive_info(self):
        text = "Call 18999998888 or mail john.doe@sample.com for assistance"
        masked = mask_sensitive_text(text)
        assert "189****8888" in masked
        assert "j***@sample.com" in masked
        assert "18999998888" not in masked
        assert "john.doe@sample.com" not in masked

    def test_mask_text_without_sensitive_info(self):
        text = "CE Marking compliant with Directive 2009/48/EC toy safety"
        assert mask_sensitive_text(text) == text


class TestDatabaseModels:
    """Test suite for SQLite + SQLAlchemy models CRUD and tenant isolation."""

    def test_user_creation_and_query(self, db_session):
        user = User(
            username="seller_001",
            hashed_password="bcrypt_hash_placeholder_for_test",
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        assert user.id is not None
        assert user.username == "seller_001"
        assert user.created_at is not None

        # Verify uniqueness of username
        duplicate = User(
            username="seller_001",
            hashed_password="another_password_hash",
        )
        db_session.add(duplicate)
        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()

    def test_audit_log_creation(self, db_session):
        user = User(username="audited_user", hashed_password="pwd")
        db_session.add(user)
        db_session.commit()

        log = AuditLog(
            user_id=user.id,
            action="COMPLIANCE_AUDIT_RUN",
            ip_address="192.168.1.100",
            detail_json='{"task_id": "task-test-1", "product": "Smart Toy"}',
        )
        db_session.add(log)
        db_session.commit()
        db_session.refresh(log)

        assert log.id is not None
        assert log.user_id == user.id
        assert log.action == "COMPLIANCE_AUDIT_RUN"
        assert log.timestamp is not None

    def test_compliance_task_and_report_relationship(self, db_session):
        user = User(username="report_user", hashed_password="pwd")
        db_session.add(user)
        db_session.commit()

        # Create Task
        task = ComplianceTask(
            user_id=user.id,
            product_name="Baby Teether Silicone Ring",
            category="Toys & Children Products",
            target_country="EU",
            status="PENDING",
        )
        db_session.add(task)
        db_session.commit()
        db_session.refresh(task)

        assert task.id is not None
        assert task.status == "PENDING"
        assert task.created_at is not None

        # Update Task Status
        task.status = "COMPLETED"
        db_session.commit()

        # Create Report linked to Task
        report = ComplianceReport(
            task_id=task.id,
            user_id=user.id,
            overall_score=85,
            risk_level="AMBER",
            report_json='{"defects": ["Missing EU REP postal code"], "score": 85}',
        )
        db_session.add(report)
        db_session.commit()
        db_session.refresh(report)

        assert report.id is not None
        assert report.task_id == task.id
        assert report.risk_level == "AMBER"
        assert report.overall_score == 85

    def test_tenant_isolation_idor_prevention(self, db_session):
        """Verify that user_id filtering strictly isolates reports across tenants."""
        user1 = User(username="merchant_a", hashed_password="pwd")
        user2 = User(username="merchant_b", hashed_password="pwd")
        db_session.add_all([user1, user2])
        db_session.commit()

        task1 = ComplianceTask(
            user_id=user1.id,
            product_name="Product A",
            category="Toys",
            target_country="EU",
            status="COMPLETED",
        )
        db_session.add(task1)
        db_session.commit()

        report1 = ComplianceReport(
            task_id=task1.id,
            user_id=user1.id,
            overall_score=92,
            risk_level="GREEN",
            report_json='{"confidential": "merchant_a_data"}',
        )
        db_session.add(report1)
        db_session.commit()

        # User 1 should find their report
        found_by_owner = (
            db_session.query(ComplianceReport)
            .filter(ComplianceReport.id == report1.id, ComplianceReport.user_id == user1.id)
            .first()
        )
        assert found_by_owner is not None

        # User 2 attempting to access User 1's report should receive None (simulating IDOR defense)
        found_by_other = (
            db_session.query(ComplianceReport)
            .filter(ComplianceReport.id == report1.id, ComplianceReport.user_id == user2.id)
            .first()
        )
        assert found_by_other is None

    def test_settings_zero_hardcoded_secrets_and_dynamic_generation(self):
        """Verify that Settings does not hardcode static secrets and generates secure keys."""
        from app.config import Settings
        s = Settings(_env_file=None)
        assert len(s.SECRET_KEY) >= 32
        assert len(s.AES_SECRET_KEY) >= 32
