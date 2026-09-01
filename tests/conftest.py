import pytest

from app.db import Base, SessionLocal, engine
from app.models import AuditEvent, ControllerNonce, ResultArtifact, ScanJob, ScanResult, Target


@pytest.fixture(scope="session", autouse=True)
def init_db():
    """Ensure all SQLAlchemy tables are created for tests."""
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture(autouse=True)
def clean_db():
    """Ensure each test starts with a clean slate for jobs and nonces."""
    with SessionLocal() as db:
        db.query(ResultArtifact).delete()
        db.query(ScanResult).delete()
        db.query(ScanJob).delete()
        db.query(ControllerNonce).delete()
        db.query(AuditEvent).delete()
        db.query(Target).delete()
        db.commit()
    yield
