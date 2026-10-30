import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime
from sqlalchemy.orm import relationship

from app.db.session import Base


def _utc_now():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(64), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=_utc_now, nullable=False)

    tasks = relationship("ComplianceTask", back_populates="user", cascade="all, delete-orphan")
    reports = relationship("ComplianceReport", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    action = Column(String(64), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    detail_json = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=_utc_now, nullable=False, index=True)

    user = relationship("User", back_populates="audit_logs")


class ComplianceTask(Base):
    __tablename__ = "compliance_tasks"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    product_name = Column(String(255), nullable=False)
    category = Column(String(128), nullable=False)
    target_country = Column(String(64), default="EU", nullable=False)
    status = Column(String(32), default="PENDING", nullable=False, index=True)
    created_at = Column(DateTime, default=_utc_now, nullable=False)

    user = relationship("User", back_populates="tasks")
    report = relationship("ComplianceReport", back_populates="task", uselist=False, cascade="all, delete-orphan")


class ComplianceReport(Base):
    __tablename__ = "compliance_reports"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    task_id = Column(String(36), ForeignKey("compliance_tasks.id"), nullable=False, unique=True, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    overall_score = Column(Integer, nullable=False)
    risk_level = Column(String(16), nullable=False, index=True)
    report_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=_utc_now, nullable=False)

    task = relationship("ComplianceTask", back_populates="report")
    user = relationship("User", back_populates="reports")
