from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, call
from uuid import uuid4

import pytest


# ==================== Fixtures ====================


@pytest.fixture
def entity_id():
    """Generate a test entity ID."""
    return uuid4()


@pytest.fixture
def user_id():
    """Generate a test user ID."""
    return uuid4()


@pytest.fixture
def document_id():
    """Generate a test document ID."""
    return uuid4()


@pytest.fixture
def mock_document(document_id, entity_id, user_id):
    """Create a mock uploaded document."""
    return SimpleNamespace(
        id=document_id,
        status="uploaded",
        filename="agreement.pdf",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        entity_type="issuer",
        entity_id=entity_id,
        token_id=1,
        document_type="operating_agreement",
        mime_type="application/pdf",
        size_bytes=1024,
        storage_bucket="test-bucket",
        storage_key="documents/test-key/agreement.pdf",
        sha256_hash="a" * 64,
        uploaded_by=user_id,
        verified_by=None,
        archived_by=None,
        archived_at=None,
        hash_verified_at=None,
        on_chain_reference=None,
        metadata_json={"description": "Operating agreement"},
    )


@pytest.fixture
def mock_verified_document(mock_document, user_id):
    """Create a mock verified document."""
    doc = SimpleNamespace(**vars(mock_document))
    doc.status = "verified"
    doc.verified_by = user_id
    doc.hash_verified_at = datetime.now(timezone.utc)
    doc.on_chain_reference = "tx-abc123"
    return doc


@pytest.fixture
def mock_archived_document(mock_document, user_id):
    """Create a mock archived document."""
    doc = SimpleNamespace(**vars(mock_document))
    doc.status = "archived"
    doc.archived_by = user_id
    doc.archived_at = datetime.now(timezone.utc)
    return doc


# ==================== Helper Functions ====================


def create_upload_form_data(entity_id: str, user_id: str) -> dict:
    """Create multipart form data for document upload."""
    return {
        "entity_id": str(entity_id),
        "entity_type": "issuer",
        "document_type": "operating_agreement",
        "uploaded_by": str(user_id),
        "token_id": "1",
        "metadata": '{"description": "Operating agreement"}',
    }


def assert_audit_event_published(mock_audit_publisher, action: str, actor_id: str, entity_id: str):
    """Assert that an audit event was published with expected fields."""
    mock_audit_publisher.publish_event.assert_called_once()
    call_kwargs = mock_audit_publisher.publish_event.call_args[1]
    
    assert call_kwargs["action"] == action
    assert str(call_kwargs["actor_id"]) == str(actor_id)
    assert str(call_kwargs["entity_id"]) == str(entity_id)
    assert call_kwargs["actor_type"] == "user"
    assert call_kwargs["entity_type"] == "document"
    assert isinstance(call_kwargs["details"], dict)


# ==================== Document Upload Tests ====================


@pytest.mark.anyio("asyncio")
async def test_upload_document_success(async_client, aws_environment, mock_document, entity_id, user_id):
    """Test successful document upload returns 201 with document metadata."""
    mock_service = aws_environment["mock_document_service"]
    mock_service.upload_document = AsyncMock(return_value=mock_document)

    response = await async_client.post(
        "/api/v1/documents/upload",
        data=create_upload_form_data(entity_id, user_id),
        files={"file": ("agreement.pdf", b"dummy-pdf-data", "application/pdf")},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["id"] == str(mock_document.id)
    assert body["status"] == "uploaded"
    assert body["filename"] == "agreement.pdf"
    assert body["sha256_hash"] == mock_document.sha256_hash


@pytest.mark.anyio("asyncio")
async def test_upload_document_with_invalid_metadata(async_client, entity_id, user_id):
    """Test upload with invalid JSON metadata returns 400."""
    response = await async_client.post(
        "/api/v1/documents/upload",
        data={
            **create_upload_form_data(entity_id, user_id),
            "metadata": "invalid-json",
        },
        files={"file": ("agreement.pdf", b"dummy-pdf-data", "application/pdf")},
    )

    assert response.status_code == 400
    assert "metadata must be valid JSON" in response.json()["detail"]


# ==================== Document Verification Tests ====================


@pytest.mark.anyio("asyncio")
async def test_verify_document_success(async_client, aws_environment, mock_verified_document, document_id, user_id):
    """Test successful document verification returns verified status."""
    mock_service = aws_environment["mock_document_service"]
    mock_service.verify_document = AsyncMock(return_value=mock_verified_document)

    response = await async_client.post(
        "/api/v1/documents/verify",
        json={"document_id": str(document_id), "verifier_id": str(user_id)},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "verified"
    assert body["verified_by"] == str(user_id)
    assert body["on_chain_reference"] == "tx-abc123"
    assert body["hash_verified_at"] is not None


@pytest.mark.anyio("asyncio")
async def test_verify_document_not_found(async_client, aws_environment, document_id, user_id):
    """Test verification of non-existent document returns 404."""
    from app.services.document_service import DocumentNotFoundError
    
    mock_service = aws_environment["mock_document_service"]
    mock_service.verify_document = AsyncMock(side_effect=DocumentNotFoundError("Document not found"))

    response = await async_client.post(
        "/api/v1/documents/verify",
        json={"document_id": str(document_id), "verifier_id": str(user_id)},
    )

    assert response.status_code == 404


# ==================== Document Listing Tests ====================


@pytest.mark.anyio("asyncio")
async def test_list_documents_success(async_client, aws_environment, mock_document, entity_id):
    """Test listing documents for an entity returns document array."""
    mock_service = aws_environment["mock_document_service"]
    mock_service.list_documents = AsyncMock(return_value=[mock_document])

    response = await async_client.get(
        f"/api/v1/documents/{entity_id}",
    )

    assert response.status_code == 200
    body = response.json()
    assert "documents" in body
    assert len(body["documents"]) == 1
    assert body["documents"][0]["id"] == str(mock_document.id)


@pytest.mark.anyio("asyncio")
async def test_list_documents_empty_result(async_client, aws_environment, entity_id):
    """Test listing documents with no results returns empty array."""
    mock_service = aws_environment["mock_document_service"]
    mock_service.list_documents = AsyncMock(return_value=[])

    response = await async_client.get(
        f"/api/v1/documents/{entity_id}",
    )

    assert response.status_code == 200
    body = response.json()
    assert body["documents"] == []


# ==================== Document Download Tests ====================


@pytest.mark.anyio("asyncio")
async def test_generate_download_url_success(async_client, aws_environment, document_id, user_id):
    """Test generating download URL returns presigned URL."""
    mock_service = aws_environment["mock_document_service"]
    mock_service.generate_download_url = AsyncMock(
        return_value=(SimpleNamespace(id=document_id), "https://s3.example.com/presigned-url?token=abc")
    )

    response = await async_client.get(
        f"/api/v1/documents/{document_id}/download",
        params={"requestor_id": str(user_id)},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["document_id"] == str(document_id)
    assert body["download_url"].startswith("https://")
    assert "expires_in_seconds" in body


@pytest.mark.anyio("asyncio")
async def test_generate_download_url_permission_denied(async_client, aws_environment, document_id, user_id):
    """Test download URL generation with insufficient permissions returns 403."""
    mock_service = aws_environment["mock_document_service"]
    mock_service.generate_download_url = AsyncMock(side_effect=PermissionError("Download not authorized"))

    response = await async_client.get(
        f"/api/v1/documents/{document_id}/download",
        params={"requestor_id": str(user_id)},
    )

    assert response.status_code == 403


@pytest.mark.anyio("asyncio")
async def test_relink_document_success(async_client, aws_environment, mock_document, document_id, user_id):
    """Test relinking a document associates it with a new entity and returns updated metadata."""
    from app.models.document import DocumentEntityType

    mock_service = aws_environment["mock_document_service"]
    mock_service.relink_document = AsyncMock(return_value=mock_document)

    new_entity_id = uuid4()

    response = await async_client.post(
        f"/api/v1/documents/{document_id}/relink",
        json={
            "new_entity_id": str(new_entity_id),
            "new_entity_type": "issuer",
            "relinked_by": str(user_id),
            "token_id": 5,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(mock_document.id)

    await_kwargs = mock_service.relink_document.await_args.kwargs
    assert await_kwargs["document_id"] == document_id
    assert await_kwargs["new_entity_id"] == new_entity_id
    assert await_kwargs["new_entity_type"] == DocumentEntityType.ISSUER
    assert await_kwargs["relinked_by"] == user_id
    assert await_kwargs["token_id"] == 5


# ==================== Document Archive Tests ====================


@pytest.mark.anyio("asyncio")
async def test_archive_document_success(async_client, aws_environment, mock_archived_document, document_id, user_id):
    """Test archiving document returns archived status with timestamp."""
    mock_service = aws_environment["mock_document_service"]
    mock_service.archive_document = AsyncMock(return_value=mock_archived_document)

    response = await async_client.delete(
        f"/api/v1/documents/{document_id}",
        params={"archived_by": str(user_id)},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "archived"
    assert body["archived_at"] is not None


# ==================== Audit Event Emission Tests ====================


@pytest.mark.anyio("asyncio")
async def test_audit_event_emitted_on_upload(entity_id, user_id, document_id):
    """Test that document.uploaded audit event is emitted after successful upload."""
    from app.services.audit_event_publisher import AuditEventPublisher
    from app.services.document_service import DocumentService
    from app.services.storage_service import StorageService
    from app.services.hashing_service import HashingService
    from app.services.blockchain_service import BlockchainService
    from app.services.epr_service_mock import EprServiceMock
    from app.events.publisher import DocumentEventPublisher
    from app.schemas.document import DocumentUploadMetadata, DocumentMetadata
    from app.models.document import DocumentEntityType, DocumentType
    from unittest.mock import AsyncMock, MagicMock, Mock
    from fastapi import UploadFile

    # Create mocks
    mock_storage = MagicMock(spec=StorageService)
    mock_storage.upload_document = AsyncMock(return_value=("s3-key", "version-1"))
    
    mock_hashing = MagicMock(spec=HashingService)
    mock_hashing.compute_sha256 = Mock(return_value="a" * 64)
    
    mock_audit_publisher = MagicMock(spec=AuditEventPublisher)
    mock_audit_publisher.publish_event = AsyncMock()
    
    mock_epr = MagicMock(spec=EprServiceMock)
    mock_epr.is_authorized = AsyncMock(return_value=True)
    
    mock_blockchain = MagicMock(spec=BlockchainService)
    mock_event_publisher = MagicMock(spec=DocumentEventPublisher)
    mock_event_publisher.publish = AsyncMock()

    # Create document service with mocked dependencies
    document_service = DocumentService(
        storage_service=mock_storage,
        hashing_service=mock_hashing,
        audit_event_publisher=mock_audit_publisher,
        access_control_service=mock_epr,
        blockchain_service=mock_blockchain,
        event_publisher=mock_event_publisher,
    )

    # Create mock file and session
    mock_file = MagicMock(spec=UploadFile)
    mock_file.filename = "test.pdf"
    mock_file.content_type = "application/pdf"
    mock_file.file = MagicMock()
    mock_file.file.read = Mock(return_value=b"test-content")
    mock_file.file.seek = Mock()
    mock_file.file.tell = Mock(return_value=100)

    mock_session = AsyncMock()
    mock_session.add = Mock()
    mock_session.flush = AsyncMock()
    # Mock session.execute for duplicate check
    mock_session.execute = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=None)  # No duplicate
    mock_session.execute.return_value = mock_result

    # Create upload metadata
    metadata = DocumentUploadMetadata(
        entity_id=entity_id,
        entity_type=DocumentEntityType.ISSUER,
        document_type=DocumentType.OPERATING_AGREEMENT,
        uploaded_by=user_id,
    )

    # Execute upload
    await document_service.upload_document(mock_session, file=mock_file, metadata=metadata)

    # Verify audit event was published
    assert_audit_event_published(
        mock_audit_publisher,
        action="document.uploaded",
        actor_id=user_id,
        entity_id=mock_session.add.call_args[0][0].id,
    )


@pytest.mark.anyio("asyncio")
async def test_audit_event_emitted_on_verify_success(entity_id, user_id, document_id):
    """Test that document.verified audit event is emitted on valid re-hash."""
    from app.services.audit_event_publisher import AuditEventPublisher
    from app.services.document_service import DocumentService
    from app.services.storage_service import StorageService
    from app.services.hashing_service import HashingService
    from app.services.blockchain_service import BlockchainService
    from app.services.epr_service_mock import EprServiceMock
    from app.events.publisher import DocumentEventPublisher
    from app.models.document import Document, DocumentEntityType, DocumentType, DocumentStatus
    from unittest.mock import AsyncMock, MagicMock, Mock
    import hashlib

    # Create a mock document
    mock_document = Document(
        id=document_id,
        entity_type=DocumentEntityType.ISSUER,
        entity_id=entity_id,
        document_type=DocumentType.OPERATING_AGREEMENT,
        filename="test.pdf",
        mime_type="application/pdf",
        size_bytes=100,
        storage_bucket="test-bucket",
        storage_key="test-key",
        sha256_hash="a" * 64,
        status=DocumentStatus.UPLOADED,
        uploaded_by=user_id,
    )

    # Create mocks
    mock_storage = MagicMock(spec=StorageService)
    
    async def mock_stream():
        yield b"test-content"
    
    mock_storage.stream_document = Mock(return_value=mock_stream())
    
    mock_hashing = MagicMock(spec=HashingService)
    mock_hash_obj = hashlib.sha256()
    mock_hash_obj.update(b"test-content")
    # Make the computed hash match the document hash
    mock_hashing.create_digest = Mock(return_value=MagicMock(
        update=Mock(),
        hexdigest=Mock(return_value="a" * 64)
    ))
    
    mock_audit_publisher = MagicMock(spec=AuditEventPublisher)
    mock_audit_publisher.publish_event = AsyncMock()
    
    mock_epr = MagicMock(spec=EprServiceMock)
    mock_epr.is_authorized = AsyncMock(return_value=True)
    
    mock_blockchain = MagicMock(spec=BlockchainService)
    mock_blockchain.register_document = AsyncMock(return_value="tx-123")
    
    mock_event_publisher = MagicMock(spec=DocumentEventPublisher)
    mock_event_publisher.publish = AsyncMock()

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock()
    mock_session.execute.return_value.scalar_one_or_none = Mock(return_value=mock_document)

    # Create document service
    document_service = DocumentService(
        storage_service=mock_storage,
        hashing_service=mock_hashing,
        audit_event_publisher=mock_audit_publisher,
        access_control_service=mock_epr,
        blockchain_service=mock_blockchain,
        event_publisher=mock_event_publisher,
    )

    # Execute verification
    await document_service.verify_document(mock_session, document_id=document_id, verifier_id=user_id)

    # Verify audit event was published with correct action
    assert_audit_event_published(
        mock_audit_publisher,
        action="document.verified",
        actor_id=user_id,
        entity_id=document_id,
    )


@pytest.mark.anyio("asyncio")
async def test_audit_event_emitted_on_verify_mismatch(entity_id, user_id, document_id):
    """Test that document.mismatch audit event is emitted on hash mismatch (corruption detected)."""
    from app.services.audit_event_publisher import AuditEventPublisher
    from app.services.document_service import DocumentService
    from app.services.storage_service import StorageService
    from app.services.hashing_service import HashingService
    from app.services.blockchain_service import BlockchainService
    from app.services.epr_service_mock import EprServiceMock
    from app.events.publisher import DocumentEventPublisher
    from app.models.document import Document, DocumentEntityType, DocumentType, DocumentStatus
    from unittest.mock import AsyncMock, MagicMock, Mock

    # Create a mock document with a specific hash
    mock_document = Document(
        id=document_id,
        entity_type=DocumentEntityType.ISSUER,
        entity_id=entity_id,
        document_type=DocumentType.OPERATING_AGREEMENT,
        filename="test.pdf",
        mime_type="application/pdf",
        size_bytes=100,
        storage_bucket="test-bucket",
        storage_key="test-key",
        sha256_hash="original_hash_123",  # Original hash
        status=DocumentStatus.UPLOADED,
        uploaded_by=user_id,
    )

    # Create mocks
    mock_storage = MagicMock(spec=StorageService)
    
    async def mock_stream():
        yield b"corrupted-content"  # Different content
    
    mock_storage.stream_document = Mock(return_value=mock_stream())
    
    mock_hashing = MagicMock(spec=HashingService)
    # Return a different hash to simulate corruption
    mock_hashing.create_digest = Mock(return_value=MagicMock(
        update=Mock(),
        hexdigest=Mock(return_value="corrupted_hash_456")
    ))
    
    mock_audit_publisher = MagicMock(spec=AuditEventPublisher)
    mock_audit_publisher.publish_event = AsyncMock()
    
    mock_epr = MagicMock(spec=EprServiceMock)
    mock_epr.is_authorized = AsyncMock(return_value=True)
    
    mock_blockchain = MagicMock(spec=BlockchainService)
    mock_event_publisher = MagicMock(spec=DocumentEventPublisher)
    mock_event_publisher.publish = AsyncMock()

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock()
    mock_session.execute.return_value.scalar_one_or_none = Mock(return_value=mock_document)

    # Create document service
    document_service = DocumentService(
        storage_service=mock_storage,
        hashing_service=mock_hashing,
        audit_event_publisher=mock_audit_publisher,
        access_control_service=mock_epr,
        blockchain_service=mock_blockchain,
        event_publisher=mock_event_publisher,
    )

    # Execute verification
    await document_service.verify_document(mock_session, document_id=document_id, verifier_id=user_id)

    # Verify audit event was published with mismatch action
    assert_audit_event_published(
        mock_audit_publisher,
        action="document.mismatch",
        actor_id=user_id,
        entity_id=document_id,
    )
    
    # Verify details contain both hashes
    call_kwargs = mock_audit_publisher.publish_event.call_args[1]
    assert "expected_hash" in call_kwargs["details"]
    assert "calculated_hash" in call_kwargs["details"]
    assert call_kwargs["details"]["expected_hash"] == "original_hash_123"
    assert call_kwargs["details"]["calculated_hash"] == "corrupted_hash_456"


@pytest.mark.anyio("asyncio")
async def test_audit_event_emitted_on_relink_success():
    """Test that document.relinked audit event captures old and new entity information."""
    from app.services.audit_event_publisher import AuditEventPublisher
    from app.services.document_service import DocumentService
    from app.services.storage_service import StorageService
    from app.services.hashing_service import HashingService
    from app.services.blockchain_service import BlockchainService
    from app.services.epr_service_mock import EprServiceMock
    from app.events.publisher import DocumentEventPublisher
    from app.models.document import Document, DocumentEntityType, DocumentType, DocumentStatus
    from unittest.mock import AsyncMock, MagicMock, Mock

    # Existing document state
    old_entity_id = uuid4()
    new_entity_id = uuid4()
    user_id = uuid4()
    document_id = uuid4()

    document = Document(
        id=document_id,
        entity_type=DocumentEntityType.ISSUER,
        entity_id=old_entity_id,
        document_type=DocumentType.OPERATING_AGREEMENT,
        filename="test.pdf",
        mime_type="application/pdf",
        size_bytes=100,
        storage_bucket="test-bucket",
        storage_key="test-key",
        sha256_hash="a" * 64,
        status=DocumentStatus.UPLOADED,
        uploaded_by=user_id,
        token_id=10,
    )

    # Mock dependencies
    mock_storage = MagicMock(spec=StorageService)
    mock_hashing = MagicMock(spec=HashingService)
    mock_audit_publisher = MagicMock(spec=AuditEventPublisher)
    mock_audit_publisher.publish_event = AsyncMock()
    mock_epr = MagicMock(spec=EprServiceMock)
    mock_epr.is_authorized = AsyncMock(return_value=True)
    mock_blockchain = MagicMock(spec=BlockchainService)
    mock_event_publisher = MagicMock(spec=DocumentEventPublisher)
    mock_event_publisher.publish = AsyncMock()

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute.return_value = mock_result
    mock_session.flush = AsyncMock()

    document_service = DocumentService(
        storage_service=mock_storage,
        hashing_service=mock_hashing,
        audit_event_publisher=mock_audit_publisher,
        access_control_service=mock_epr,
        blockchain_service=mock_blockchain,
        event_publisher=mock_event_publisher,
    )

    await document_service.relink_document(
        mock_session,
        document_id=document_id,
        new_entity_id=new_entity_id,
        new_entity_type=DocumentEntityType.DEAL,
        relinked_by=user_id,
        token_id=20,
    )

    assert document.entity_id == new_entity_id
    assert document.entity_type == DocumentEntityType.DEAL
    assert document.token_id == 20
    mock_session.flush.assert_awaited_once()

    assert_audit_event_published(
        mock_audit_publisher,
        action="document.relinked",
        actor_id=user_id,
        entity_id=document_id,
    )
    audit_kwargs = mock_audit_publisher.publish_event.call_args[1]
    details = audit_kwargs["details"]
    assert details["old_entity_id"] == str(old_entity_id)
    assert details["new_entity_id"] == str(new_entity_id)
    assert details["old_entity_type"] == DocumentEntityType.ISSUER.value
    assert details["new_entity_type"] == DocumentEntityType.DEAL.value
    assert details["token_id"] == 20

    mock_event_publisher.publish.assert_awaited_once()
    event_kwargs = mock_event_publisher.publish.await_args.kwargs
    assert event_kwargs["event_type"] == "document.relinked"
    payload = event_kwargs["payload"]
    assert payload["old_entity_id"] == str(old_entity_id)
    assert payload["new_entity_id"] == str(new_entity_id)
    assert payload["relinked_by"] == str(user_id)


@pytest.mark.anyio("asyncio")
async def test_audit_event_emitted_on_archive(entity_id, user_id, document_id):
    """Test that document.archived audit event is emitted on document archival."""
    from app.services.audit_event_publisher import AuditEventPublisher
    from app.services.document_service import DocumentService
    from app.services.storage_service import StorageService
    from app.services.hashing_service import HashingService
    from app.services.blockchain_service import BlockchainService
    from app.services.epr_service_mock import EprServiceMock
    from app.events.publisher import DocumentEventPublisher
    from app.models.document import Document, DocumentEntityType, DocumentType, DocumentStatus
    from unittest.mock import AsyncMock, MagicMock, Mock

    # Create a mock document
    mock_document = Document(
        id=document_id,
        entity_type=DocumentEntityType.ISSUER,
        entity_id=entity_id,
        document_type=DocumentType.OPERATING_AGREEMENT,
        filename="test.pdf",
        mime_type="application/pdf",
        size_bytes=100,
        storage_bucket="test-bucket",
        storage_key="test-key",
        sha256_hash="a" * 64,
        status=DocumentStatus.VERIFIED,
        uploaded_by=user_id,
    )

    # Create mocks
    mock_storage = MagicMock(spec=StorageService)
    mock_hashing = MagicMock(spec=HashingService)
    
    mock_audit_publisher = MagicMock(spec=AuditEventPublisher)
    mock_audit_publisher.publish_event = AsyncMock()
    
    mock_epr = MagicMock(spec=EprServiceMock)
    mock_epr.is_authorized = AsyncMock(return_value=True)
    
    mock_blockchain = MagicMock(spec=BlockchainService)
    mock_event_publisher = MagicMock(spec=DocumentEventPublisher)
    mock_event_publisher.publish = AsyncMock()

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock()
    mock_session.execute.return_value.scalar_one_or_none = Mock(return_value=mock_document)

    # Create document service
    document_service = DocumentService(
        storage_service=mock_storage,
        hashing_service=mock_hashing,
        audit_event_publisher=mock_audit_publisher,
        access_control_service=mock_epr,
        blockchain_service=mock_blockchain,
        event_publisher=mock_event_publisher,
    )

    # Execute archive
    await document_service.archive_document(mock_session, document_id=document_id, archived_by=user_id)

    # Verify audit event was published
    assert_audit_event_published(
        mock_audit_publisher,
        action="document.archived",
        actor_id=user_id,
        entity_id=document_id,
    )


@pytest.mark.anyio("asyncio")
async def test_audit_event_payload_schema_compliance():
    """Test that audit event payload conforms to the EPR service contract."""
    from app.services.audit_event_publisher import AuditEventPublisher
    from unittest.mock import AsyncMock, MagicMock
    from uuid import uuid4
    import json
    import httpx

    event_id = uuid4()
    actor_id = uuid4()
    entity_id = uuid4()

    mock_http_client = MagicMock(spec=httpx.AsyncClient)
    mock_http_client.post = AsyncMock(return_value=httpx.Response(201, json={"delivery_state": "delivered"}))

    publisher = AuditEventPublisher(mock_http_client)

    await publisher.publish_event(
        action="document.uploaded",
        actor_id=actor_id,
        actor_type="user",
        entity_id=entity_id,
        entity_type="document",
        details={"filename": "test.pdf"},
        correlation_id="req-123",
        event_id=event_id,
    )

    # Verify httpx client was called
    mock_http_client.post.assert_called_once()
    call_kwargs = mock_http_client.post.call_args.kwargs

    # Parse the message body
    message_body = call_kwargs["json"]

    # Validate schema compliance
    assert "event_type" in message_body
    assert message_body["event_type"] == "document.uploaded"
    assert message_body["source"] == "document_vault"
    assert "context" in message_body
    assert "payload" in message_body

    context = message_body["context"]
    assert context["actor_id"] == str(actor_id)
    assert context["actor_type"] == "user"
    assert context["entity_id"] == str(entity_id)
    assert context["entity_type"] == "document"
    
    payload = message_body["payload"]
    assert payload == {"filename": "test.pdf"}
    
    assert message_body["correlation_id"] == "req-123"


# ==================== Document Events (SQS/Internal Event Bus) Tests ====================


@pytest.mark.anyio("asyncio")
async def test_document_event_emitted_on_upload():
    """Test that document.uploaded event is emitted to internal event bus (SQS) after storage."""
    from app.services.audit_event_publisher import AuditEventPublisher
    from app.services.document_service import DocumentService
    from app.services.storage_service import StorageService
    from app.services.hashing_service import HashingService
    from app.services.blockchain_service import BlockchainService
    from app.services.epr_service_mock import EprServiceMock
    from app.events.publisher import DocumentEventPublisher
    from app.schemas.document import DocumentUploadMetadata, DocumentMetadata
    from app.models.document import DocumentEntityType, DocumentType
    from unittest.mock import AsyncMock, MagicMock, Mock
    from fastapi import UploadFile

    entity_id = uuid4()
    user_id = uuid4()

    # Create mocks
    mock_storage = MagicMock(spec=StorageService)
    mock_storage.upload_document = AsyncMock(return_value=("s3-key", "version-1"))
    
    mock_hashing = MagicMock(spec=HashingService)
    mock_hashing.compute_sha256 = Mock(return_value="a" * 64)
    
    mock_audit_publisher = MagicMock(spec=AuditEventPublisher)
    mock_audit_publisher.publish_event = AsyncMock()
    
    mock_epr = MagicMock(spec=EprServiceMock)
    mock_epr.is_authorized = AsyncMock(return_value=True)
    
    mock_blockchain = MagicMock(spec=BlockchainService)
    mock_event_publisher = MagicMock(spec=DocumentEventPublisher)
    mock_event_publisher.publish = AsyncMock()

    # Create document service with mocked dependencies
    document_service = DocumentService(
        storage_service=mock_storage,
        hashing_service=mock_hashing,
        audit_event_publisher=mock_audit_publisher,
        access_control_service=mock_epr,
        blockchain_service=mock_blockchain,
        event_publisher=mock_event_publisher,
    )

    # Create mock file and session
    mock_file = MagicMock(spec=UploadFile)
    mock_file.filename = "test.pdf"
    mock_file.content_type = "application/pdf"
    mock_file.file = MagicMock()
    mock_file.file.read = Mock(return_value=b"test-content")
    mock_file.file.seek = Mock()
    mock_file.file.tell = Mock(return_value=100)

    mock_session = AsyncMock()
    mock_session.add = Mock()
    mock_session.flush = AsyncMock()
    # Mock session.execute for duplicate check
    mock_session.execute = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=None)  # No duplicate
    mock_session.execute.return_value = mock_result

    # Create upload metadata
    metadata = DocumentUploadMetadata(
        entity_id=entity_id,
        entity_type=DocumentEntityType.ISSUER,
        document_type=DocumentType.OPERATING_AGREEMENT,
        uploaded_by=user_id,
    )

    # Execute upload
    await document_service.upload_document(mock_session, file=mock_file, metadata=metadata)

    # Verify document event was published to internal event bus (SQS)
    mock_event_publisher.publish.assert_called_once()
    call_kwargs = mock_event_publisher.publish.call_args[1]
    
    assert call_kwargs["event_type"] == "document.uploaded"
    assert "payload" in call_kwargs
    payload = call_kwargs["payload"]
    assert "document_id" in payload
    assert payload["entity_type"] == "issuer"
    assert payload["entity_id"] == str(entity_id)
    assert "sha256_hash" in payload
    assert payload["status"] == "uploaded"


@pytest.mark.anyio("asyncio")
async def test_document_event_emitted_on_verify_success():
    """Test that document.verified event is emitted to internal event bus on valid re-hash."""
    from app.services.audit_event_publisher import AuditEventPublisher
    from app.services.document_service import DocumentService
    from app.services.storage_service import StorageService
    from app.services.hashing_service import HashingService
    from app.services.blockchain_service import BlockchainService
    from app.services.epr_service_mock import EprServiceMock
    from app.events.publisher import DocumentEventPublisher
    from app.models.document import Document, DocumentEntityType, DocumentType, DocumentStatus
    from unittest.mock import AsyncMock, MagicMock, Mock

    entity_id = uuid4()
    user_id = uuid4()
    document_id = uuid4()

    # Create a mock document
    mock_document = Document(
        id=document_id,
        entity_type=DocumentEntityType.ISSUER,
        entity_id=entity_id,
        document_type=DocumentType.OPERATING_AGREEMENT,
        filename="test.pdf",
        mime_type="application/pdf",
        size_bytes=100,
        storage_bucket="test-bucket",
        storage_key="test-key",
        sha256_hash="a" * 64,
        status=DocumentStatus.UPLOADED,
        uploaded_by=user_id,
    )

    # Create mocks
    mock_storage = MagicMock(spec=StorageService)
    
    async def mock_stream():
        yield b"test-content"
    
    mock_storage.stream_document = Mock(return_value=mock_stream())
    
    mock_hashing = MagicMock(spec=HashingService)
    mock_hashing.create_digest = Mock(return_value=MagicMock(
        update=Mock(),
        hexdigest=Mock(return_value="a" * 64)
    ))
    
    mock_audit_publisher = MagicMock(spec=AuditEventPublisher)
    mock_audit_publisher.publish_event = AsyncMock()
    
    mock_epr = MagicMock(spec=EprServiceMock)
    mock_epr.is_authorized = AsyncMock(return_value=True)
    
    mock_blockchain = MagicMock(spec=BlockchainService)
    mock_blockchain.register_document = AsyncMock(return_value="tx-123")
    
    mock_event_publisher = MagicMock(spec=DocumentEventPublisher)
    mock_event_publisher.publish = AsyncMock()

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock()
    mock_session.execute.return_value.scalar_one_or_none = Mock(return_value=mock_document)

    # Create document service
    document_service = DocumentService(
        storage_service=mock_storage,
        hashing_service=mock_hashing,
        audit_event_publisher=mock_audit_publisher,
        access_control_service=mock_epr,
        blockchain_service=mock_blockchain,
        event_publisher=mock_event_publisher,
    )

    # Execute verification
    await document_service.verify_document(mock_session, document_id=document_id, verifier_id=user_id)

    # Verify document event was published to internal event bus
    mock_event_publisher.publish.assert_called_once()
    call_kwargs = mock_event_publisher.publish.call_args[1]
    
    assert call_kwargs["event_type"] == "document.verified"
    assert "payload" in call_kwargs
    payload = call_kwargs["payload"]
    assert payload["document_id"] == str(document_id)
    assert payload["entity_type"] == "issuer"
    assert payload["entity_id"] == str(entity_id)
    assert "sha256_hash" in payload


@pytest.mark.anyio("asyncio")
async def test_document_event_emitted_on_verify_mismatch():
    """Test that document.mismatch event is emitted to internal event bus on corruption detection."""
    from app.services.audit_event_publisher import AuditEventPublisher
    from app.services.document_service import DocumentService
    from app.services.storage_service import StorageService
    from app.services.hashing_service import HashingService
    from app.services.blockchain_service import BlockchainService
    from app.services.epr_service_mock import EprServiceMock
    from app.events.publisher import DocumentEventPublisher
    from app.models.document import Document, DocumentEntityType, DocumentType, DocumentStatus
    from unittest.mock import AsyncMock, MagicMock, Mock

    entity_id = uuid4()
    user_id = uuid4()
    document_id = uuid4()

    # Create a mock document with a specific hash
    mock_document = Document(
        id=document_id,
        entity_type=DocumentEntityType.ISSUER,
        entity_id=entity_id,
        document_type=DocumentType.OPERATING_AGREEMENT,
        filename="test.pdf",
        mime_type="application/pdf",
        size_bytes=100,
        storage_bucket="test-bucket",
        storage_key="test-key",
        sha256_hash="original_hash_123",
        status=DocumentStatus.UPLOADED,
        uploaded_by=user_id,
    )

    # Create mocks
    mock_storage = MagicMock(spec=StorageService)
    
    async def mock_stream():
        yield b"corrupted-content"
    
    mock_storage.stream_document = Mock(return_value=mock_stream())
    
    mock_hashing = MagicMock(spec=HashingService)
    mock_hashing.create_digest = Mock(return_value=MagicMock(
        update=Mock(),
        hexdigest=Mock(return_value="corrupted_hash_456")
    ))
    
    mock_audit_publisher = MagicMock(spec=AuditEventPublisher)
    mock_audit_publisher.publish_event = AsyncMock()
    
    mock_epr = MagicMock(spec=EprServiceMock)
    mock_epr.is_authorized = AsyncMock(return_value=True)
    
    mock_blockchain = MagicMock(spec=BlockchainService)
    mock_event_publisher = MagicMock(spec=DocumentEventPublisher)
    mock_event_publisher.publish = AsyncMock()

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock()
    mock_session.execute.return_value.scalar_one_or_none = Mock(return_value=mock_document)

    # Create document service
    document_service = DocumentService(
        storage_service=mock_storage,
        hashing_service=mock_hashing,
        audit_event_publisher=mock_audit_publisher,
        access_control_service=mock_epr,
        blockchain_service=mock_blockchain,
        event_publisher=mock_event_publisher,
    )

    # Execute verification
    await document_service.verify_document(mock_session, document_id=document_id, verifier_id=user_id)

    # Verify document event was published to internal event bus
    mock_event_publisher.publish.assert_called_once()
    call_kwargs = mock_event_publisher.publish.call_args[1]
    
    assert call_kwargs["event_type"] == "document.mismatch"
    assert "payload" in call_kwargs
    payload = call_kwargs["payload"]
    assert payload["document_id"] == str(document_id)
    assert payload["expected_hash"] == "original_hash_123"
    assert payload["calculated_hash"] == "corrupted_hash_456"
    assert payload["entity_id"] == str(entity_id)


@pytest.mark.anyio("asyncio")
async def test_document_event_payload_schema_compliance():
    """Test that document event payload conforms to internal event bus schema."""
    from app.events.publisher import DocumentEventPublisher
    from unittest.mock import AsyncMock, MagicMock, patch
    from uuid import uuid4
    import json

    document_id = uuid4()
    entity_id = uuid4()

    mock_sqs_client = MagicMock()
    mock_sqs_client.send_message = AsyncMock()

    publisher = DocumentEventPublisher()

    # Patch the SQS client creation
    with patch.object(publisher._session, 'client') as mock_client_context:
        mock_client_context.return_value.__aenter__.return_value = mock_sqs_client
        
        await publisher.publish(
            event_type="document.uploaded",
            payload={
                "document_id": str(document_id),
                "entity_type": "issuer",
                "entity_id": str(entity_id),
                "sha256_hash": "a" * 64,
                "status": "uploaded",
            }
        )

    # Verify SQS send_message was called
    mock_sqs_client.send_message.assert_called_once()
    call_kwargs = mock_sqs_client.send_message.call_args[1]

    # Parse the message body
    message_body = json.loads(call_kwargs["MessageBody"])

    # Validate schema compliance
    assert "event_type" in message_body
    assert message_body["event_type"] == "document.uploaded"
    assert "occurred_at" in message_body
    assert "payload" in message_body
    
    payload = message_body["payload"]
    assert payload["document_id"] == str(document_id)
    assert payload["entity_type"] == "issuer"
    assert payload["entity_id"] == str(entity_id)
    assert payload["sha256_hash"] == "a" * 64
    assert payload["status"] == "uploaded"
    
    # Validate ISO-8601 timestamp format
    from datetime import datetime
    datetime.fromisoformat(message_body["occurred_at"].replace("Z", "+00:00"))

    # Verify message attributes
    assert "MessageAttributes" in call_kwargs
    assert call_kwargs["MessageAttributes"]["event_type"]["StringValue"] == "document.uploaded"


# ==================== Signature API Tests ====================


@pytest.mark.anyio("asyncio")
async def test_request_document_signatures(async_client, aws_environment, mock_document, document_id, user_id):
    mock_signature_service = aws_environment["mock_signature_service"]
    document_with_signatures = SimpleNamespace(**vars(mock_document))
    document_with_signatures.signature_state = "PENDING"
    document_with_signatures.signatures_json = []
    mock_signature_service.request_signatures = AsyncMock(return_value=document_with_signatures)

    payload = {
        "requested_by": str(user_id),
        "signers": [
            {
                "user_id": str(user_id),
                "email": "user@example.com",
                "role": "issuer",
                "routing_order": 1,
            }
        ],
        "email_subject": "Please sign",
    }

    response = await async_client.post(f"/api/v1/documents/{document_id}/signatures/request", json=payload)

    assert response.status_code == 200
    mock_signature_service.request_signatures.assert_awaited_once()


@pytest.mark.anyio("asyncio")
async def test_get_signature_status(async_client, aws_environment, mock_document, document_id):
    mock_service = aws_environment["mock_document_service"]
    document_with_signatures = SimpleNamespace(**vars(mock_document))
    document_with_signatures.signature_state = "PENDING"
    document_with_signatures.signatures_json = []
    mock_service.get_document = AsyncMock(return_value=document_with_signatures)

    response = await async_client.get(f"/api/v1/documents/{document_id}/signatures/status")

    assert response.status_code == 200
    mock_service.get_document.assert_awaited_once()


@pytest.mark.anyio("asyncio")
async def test_docusign_webhook(async_client, aws_environment):
    mock_signature_service = aws_environment["mock_signature_service"]
    mock_signature_service.process_webhook_notification = AsyncMock()

    payload = {
        "envelopeId": "env-123",
        "recipients": {
            "signers": [
                {"recipientId": "1", "status": "completed"},
            ]
        },
    }

    response = await async_client.post("/api/v1/documents/signatures/webhook/docusign", json=payload)

    assert response.status_code == 202
    mock_signature_service.process_webhook_notification.assert_awaited_once()
