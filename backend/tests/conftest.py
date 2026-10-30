import os
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Ensure config uses test settings
os.environ["AES_SECRET_KEY"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
os.environ["SECRET_KEY"] = "test_secret_jwt_key_for_testing_purposes_only"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from app.db.models import Base
from app.db.session import SessionLocal


@pytest.fixture(scope="session")
def test_aes_key():
    """32-byte hex-encoded key for AES-256 testing."""
    return "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture(scope="function")
def db_session():
    """Provide an isolated in-memory SQLite database session for each test."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()
        Base.metadata.drop_all(bind=engine)
