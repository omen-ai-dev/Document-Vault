from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncGenerator, Generator
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import MagicMock

# Ensure environment variables are set (and overridden) before application settings are imported.
os.environ.setdefault("PYTEST_ASYNCIO_MODE", "auto")
os.environ.setdefault("ENVIRONMENT", "test")
# Always point tests at the local sqlite DB regardless of existing env settings.
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./tests/test.db"
os.environ.setdefault("DATABASE_POOL_PRE_PING", "false")
os.environ.setdefault("DOCUMENT_VAULT_BUCKET", "document-vault-test")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test-access-key")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test-secret-key")
os.environ.setdefault("AUDIT_SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:116981763412:epr-audit-events")

from app.api import dependencies as dependencies_module
from app.db.session import AsyncSessionFactory
from app.main import create_app


@pytest.fixture
def aws_environment(monkeypatch) -> dict[str, object]:
    monkeypatch.setenv("AWS_S3_KMS_KEY_ID", "kms-key-alias")
    monkeypatch.setenv("DOCUMENT_EVENTS_QUEUE_URL", "http://localhost:4566/000000000000/test-queue")
    monkeypatch.setenv("EPR_MOCK_MODE", "True")

    app = create_app()
    
    # It's important to clear the cache on the dependency functions
    # to ensure mocks are applied for each test run.
    dependencies_module.get_document_service.cache_clear()
    dependencies_module.get_access_control_service.cache_clear()
    dependencies_module.get_http_client.cache_clear()
    
    # Mock the entire DocumentService for API tests
    mock_document_service = MagicMock()
    mock_signature_service = MagicMock()
    app.dependency_overrides[dependencies_module.get_document_service] = lambda: mock_document_service
    app.dependency_overrides[dependencies_module.get_document_signature_service] = lambda: mock_signature_service

    return {
        "app_instance": app,
        "mock_document_service": mock_document_service,
        "mock_signature_service": mock_signature_service,
    }


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionFactory() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def async_client(aws_environment) -> AsyncGenerator[AsyncClient, None]:
    app = aws_environment["app_instance"]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
