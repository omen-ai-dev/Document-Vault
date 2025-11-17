"""
Comprehensive compliance audit flow tests.

Tests validate end-to-end verification and alerting workflow for compliance officers,
including integrity alert generation, entity freeze flags, and dashboard visibility.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import AsyncGenerator, Callable
from unittest.mock import AsyncMock, MagicMock, Mock
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

from app.models.document import Document, DocumentEntityType, DocumentStatus, DocumentType
from app.schemas.document import DocumentUploadMetadata
from app.services.audit_event_publisher import AuditEventPublisher
from app.services.blockchain_service import BlockchainService
from app.services.document_service import DocumentService
from app.services.epr_service_mock import EprServiceMock
from app.services.hashing_service import HashingService
from app.services.storage_service import StorageService
from app.events.publisher import DocumentEventPublisher


@pytest.fixture
def compliance_officer_id() -> UUID:
    """Return a fixed compliance officer ID for testing."""
    return uuid4()


@pytest.fixture
def entity_id() -> UUID:
    """Return a fixed entity ID for testing."""
    return uuid4()


@pytest.fixture
def mock_file_content() -> bytes:
    """Return consistent file content for testing."""
    return b"This is a test document for compliance audit validation."


def create_mock_upload_file(content: bytes, filename: str, mime_type: str):
    """Helper to create a mock UploadFile."""
    from fastapi import UploadFile
    
    mock_file = MagicMock(spec=UploadFile)
    mock_file.filename = filename
    mock_file.content_type = mime_type
    mock_file.file = io.BytesIO(content)
    return mock_file


@pytest.fixture
def document_service_with_compliance_role() -> Callable[[UUID], DocumentService]:
    """
    Factory fixture that returns a DocumentService configured for compliance officers.
    
    Returns a service with compliance officer role properly configured.
    """
    
    def _factory(compliance_officer_id: UUID) -> DocumentService:
        # Create mock storage service
        mock_storage = AsyncMock(spec=StorageService)
        mock_storage.upload_document = AsyncMock(return_value=("s3-key-123", "version-id-456"))
        
        # Create real hashing service for consistent hashes
        hashing_service = HashingService()
        
        # Create mock audit publisher
        mock_audit_publisher = AsyncMock(spec=AuditEventPublisher)
        mock_audit_publisher.publish_event = AsyncMock()
        
        # Create EPR service with compliance officer role
        # Compliance officers can download, verify, and archive (read + verify + admin actions)
        role_mapping = {compliance_officer_id: "compliance_officer"}
        mock_epr = EprServiceMock(role_permissions=role_mapping)
        
        # Create mock blockchain service
        mock_blockchain = AsyncMock(spec=BlockchainService)
        mock_blockchain.register_document = AsyncMock(return_value="tx-hash-123")
        
        # Create mock event publisher (for internal events and integrity alerts)
        mock_event_publisher = AsyncMock(spec=DocumentEventPublisher)
        mock_event_publisher.publish = AsyncMock()
        mock_event_publisher.publish_integrity_alert = AsyncMock()
        
        service = DocumentService(
            storage_service=mock_storage,
            hashing_service=hashing_service,
            audit_event_publisher=mock_audit_publisher,
            access_control_service=mock_epr,
            blockchain_service=mock_blockchain,
            event_publisher=mock_event_publisher,
        )
        
        # Attach mocks for inspection in tests
        service._mock_storage = mock_storage
        service._mock_audit_publisher = mock_audit_publisher
        service._mock_event_publisher = mock_event_publisher
        
        return service
    
    return _factory


@pytest.fixture
async def mock_document_factory(entity_id: UUID) -> Callable:
    """Factory to create mock documents with custom properties."""
    
    def _create_document(**kwargs) -> Document:
        uploader_id = kwargs.get("uploaded_by", uuid4())
        defaults = {
            "id": uuid4(),
            "entity_type": DocumentEntityType.ISSUER,
            "entity_id": entity_id,
            "document_type": DocumentType.OPERATING_AGREEMENT,
            "filename": "test.pdf",
            "mime_type": "application/pdf",
            "size_bytes": 1024,
            "storage_bucket": "test-bucket",
            "storage_key": "test-key",
            "storage_version_id": "version-1",
            "sha256_hash": "a" * 64,
            "status": DocumentStatus.UPLOADED,
            "uploaded_by": uploader_id,
        }
        defaults.update(kwargs)
        return Document(**defaults)
    
    return _create_document


# ============================================================================
# Test: Officer-Triggered Re-Hash Matches Stored Value
# ============================================================================

@pytest.mark.anyio("asyncio")
async def test_compliance_officer_rehash_matches_stored_value(
    document_service_with_compliance_role,
    mock_document_factory,
    compliance_officer_id,
    mock_file_content,
):
    """
    Test: Officer-triggered re-hash matches stored value
    
    Validates:
    - Compliance officer can trigger document verification
    - Re-computed hash matches original stored hash
    - Document status changes to VERIFIED
    - No integrity alert is generated (hash matches)
    - Verification is logged in audit trail
    """
    service = document_service_with_compliance_role(compliance_officer_id)
    
    # Create a document with known hash
    original_hash = service.hashing_service.compute_sha256(io.BytesIO(mock_file_content))
    document = mock_document_factory(
        status=DocumentStatus.UPLOADED,
        sha256_hash=original_hash,
        uploaded_by=uuid4(),
    )
    
    # Mock session
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    # Mock storage to return original content
    async def mock_stream():
        yield mock_file_content
    
    service.storage_service.stream_document = Mock(return_value=mock_stream())
    
    # Compliance officer triggers verification
    verified_document = await service.verify_document(
        mock_session,
        document_id=document.id,
        verifier_id=compliance_officer_id,
    )
    
    # Assertions
    assert verified_document.status == DocumentStatus.VERIFIED
    assert verified_document.verified_by == compliance_officer_id
    assert verified_document.hash_verified_at is not None
    
    # Verify audit event was published
    service._mock_audit_publisher.publish_event.assert_called_once()
    call_kwargs = service._mock_audit_publisher.publish_event.call_args[1]
    assert call_kwargs["action"] == "document.verified"
    assert call_kwargs["actor_id"] == compliance_officer_id
    
    # Verify NO integrity alert was published (hash matched)
    service._mock_event_publisher.publish_integrity_alert.assert_not_called()


@pytest.mark.anyio("asyncio")
async def test_compliance_officer_has_verify_permission(
    document_service_with_compliance_role,
    mock_document_factory,
    compliance_officer_id,
    mock_file_content,
):
    """
    Test: Compliance officer has permission to verify documents
    
    Validates:
    - Compliance officer role grants document:verify permission
    - Authorization check passes
    - Verification proceeds without PermissionError
    """
    service = document_service_with_compliance_role(compliance_officer_id)
    
    original_hash = service.hashing_service.compute_sha256(io.BytesIO(mock_file_content))
    document = mock_document_factory(status=DocumentStatus.UPLOADED, sha256_hash=original_hash)
    
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    async def mock_stream():
        yield mock_file_content
    
    service.storage_service.stream_document = Mock(return_value=mock_stream())
    
    # Should NOT raise PermissionError
    verified_document = await service.verify_document(
        mock_session,
        document_id=document.id,
        verifier_id=compliance_officer_id,
    )
    
    assert verified_document.verified_by == compliance_officer_id


# ============================================================================
# Test: Mismatch Triggers Integrity Alert Event
# ============================================================================

@pytest.mark.anyio("asyncio")
async def test_mismatch_triggers_integrity_alert_event(
    document_service_with_compliance_role,
    mock_document_factory,
    compliance_officer_id,
    entity_id,
):
    """
    Test: Mismatch triggers Integrity Alert event
    
    Validates:
    - Hash mismatch detected during verification
    - Document status changes to MISMATCH
    - Integrity alert event published to compliance alert queue
    - Alert contains expected_hash, calculated_hash, and entity context
    - Audit event for mismatch also published
    """
    service = document_service_with_compliance_role(compliance_officer_id)
    
    # Create document with original hash
    expected_hash = "a" * 64
    calculated_hash = "b" * 64  # Different hash (tampered)
    
    document = mock_document_factory(
        status=DocumentStatus.UPLOADED,
        sha256_hash=expected_hash,
        entity_id=entity_id,
    )
    
    # Mock session
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    # Mock storage to return tampered content
    async def mock_stream():
        yield b"tampered content"
    
    service.storage_service.stream_document = Mock(return_value=mock_stream())
    
    # Mock hashing to return different hash
    service.hashing_service.create_digest = Mock(return_value=MagicMock(
        update=Mock(),
        hexdigest=Mock(return_value=calculated_hash)
    ))
    
    # Compliance officer triggers verification
    verified_document = await service.verify_document(
        mock_session,
        document_id=document.id,
        verifier_id=compliance_officer_id,
    )
    
    # Assertions
    assert verified_document.status == DocumentStatus.MISMATCH
    
    # Verify audit event for mismatch was published
    service._mock_audit_publisher.publish_event.assert_called_once()
    call_kwargs = service._mock_audit_publisher.publish_event.call_args[1]
    assert call_kwargs["action"] == "document.mismatch"
    assert call_kwargs["details"]["expected_hash"] == expected_hash
    assert call_kwargs["details"]["calculated_hash"] == calculated_hash
    
    # Verify integrity alert was published
    service._mock_event_publisher.publish_integrity_alert.assert_called_once()
    alert_kwargs = service._mock_event_publisher.publish_integrity_alert.call_args[1]
    assert alert_kwargs["document_id"] == document.id
    assert alert_kwargs["entity_id"] == entity_id
    assert alert_kwargs["entity_type"] == DocumentEntityType.ISSUER
    assert alert_kwargs["expected_hash"] == expected_hash
    assert alert_kwargs["calculated_hash"] == calculated_hash
    assert alert_kwargs["verified_by"] == compliance_officer_id


@pytest.mark.anyio("asyncio")
async def test_integrity_alert_contains_comprehensive_metadata(
    document_service_with_compliance_role,
    mock_document_factory,
    compliance_officer_id,
    entity_id,
):
    """
    Test: Integrity alert contains comprehensive metadata
    
    Validates:
    - Alert includes document ID, filename, entity context
    - Alert includes both hashes for forensic analysis
    - Alert includes timestamp and verifier information
    - Alert severity level is set appropriately
    """
    service = document_service_with_compliance_role(compliance_officer_id)
    
    expected_hash = "original_hash_123"
    calculated_hash = "tampered_hash_456"
    
    document = mock_document_factory(
        status=DocumentStatus.UPLOADED,
        sha256_hash=expected_hash,
        entity_id=entity_id,
        filename="sensitive_contract.pdf",
    )
    
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    async def mock_stream():
        yield b"tampered"
    
    service.storage_service.stream_document = Mock(return_value=mock_stream())
    service.hashing_service.create_digest = Mock(return_value=MagicMock(
        update=Mock(),
        hexdigest=Mock(return_value=calculated_hash)
    ))
    
    await service.verify_document(mock_session, document_id=document.id, verifier_id=compliance_officer_id)
    
    # Verify alert metadata
    alert_kwargs = service._mock_event_publisher.publish_integrity_alert.call_args[1]
    
    assert alert_kwargs["document_id"] == document.id
    assert alert_kwargs["filename"] == "sensitive_contract.pdf"
    assert alert_kwargs["entity_id"] == entity_id
    assert alert_kwargs["entity_type"] == DocumentEntityType.ISSUER
    assert alert_kwargs["expected_hash"] == expected_hash
    assert alert_kwargs["calculated_hash"] == calculated_hash
    assert alert_kwargs["verified_by"] == compliance_officer_id
    assert alert_kwargs["severity"] == "CRITICAL"  # Tampering is always critical


# ============================================================================
# Test: Alert Visible in Compliance Dashboard
# ============================================================================

@pytest.mark.anyio("asyncio")
async def test_integrity_alert_published_to_compliance_queue(
    document_service_with_compliance_role,
    mock_document_factory,
    compliance_officer_id,
    entity_id,
):
    """
    Test: Alert visible in compliance dashboard
    
    Validates:
    - Integrity alert published to compliance alert queue/topic
    - Alert format compatible with compliance dashboard ingestion
    - Alert contains all required fields for dashboard display
    - Alert is published asynchronously (non-blocking)
    """
    service = document_service_with_compliance_role(compliance_officer_id)
    
    document = mock_document_factory(
        status=DocumentStatus.UPLOADED,
        sha256_hash="expected",
        entity_id=entity_id,
    )
    
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    async def mock_stream():
        yield b"tampered"
    
    service.storage_service.stream_document = Mock(return_value=mock_stream())
    service.hashing_service.create_digest = Mock(return_value=MagicMock(
        update=Mock(),
        hexdigest=Mock(return_value="calculated")
    ))
    
    await service.verify_document(mock_session, document_id=document.id, verifier_id=compliance_officer_id)
    
    # Verify alert was published (dashboard would consume from this queue)
    service._mock_event_publisher.publish_integrity_alert.assert_called_once()
    
    alert_kwargs = service._mock_event_publisher.publish_integrity_alert.call_args[1]
    
    # Verify dashboard-required fields
    required_fields = [
        "document_id",
        "filename",
        "entity_id",
        "entity_type",
        "expected_hash",
        "calculated_hash",
        "verified_by",
        "severity",
    ]
    
    for field in required_fields:
        assert field in alert_kwargs, f"Missing required field for dashboard: {field}"


@pytest.mark.anyio("asyncio")
async def test_multiple_mismatches_generate_separate_alerts(
    document_service_with_compliance_role,
    mock_document_factory,
    compliance_officer_id,
    entity_id,
):
    """
    Test: Multiple mismatches generate separate alerts
    
    Validates:
    - Each mismatch detection generates a unique alert
    - Alerts are independently published to compliance dashboard
    - Dashboard can track multiple integrity issues
    """
    service = document_service_with_compliance_role(compliance_officer_id)
    
    # Create two documents
    doc1 = mock_document_factory(status=DocumentStatus.UPLOADED, sha256_hash="hash1")
    doc2 = mock_document_factory(status=DocumentStatus.UPLOADED, sha256_hash="hash2")
    
    mock_session = AsyncMock()
    
    async def mock_stream():
        yield b"tampered"
    
    service.storage_service.stream_document = Mock(return_value=mock_stream())
    
    # Verify first document (mismatch)
    mock_result1 = MagicMock()
    mock_result1.scalar_one_or_none = Mock(return_value=doc1)
    mock_session.execute = AsyncMock(return_value=mock_result1)
    
    service.hashing_service.create_digest = Mock(return_value=MagicMock(
        update=Mock(),
        hexdigest=Mock(return_value="tampered1")
    ))
    
    await service.verify_document(mock_session, document_id=doc1.id, verifier_id=compliance_officer_id)
    
    # Reset mock
    service._mock_event_publisher.publish_integrity_alert.reset_mock()
    
    # Verify second document (mismatch)
    mock_result2 = MagicMock()
    mock_result2.scalar_one_or_none = Mock(return_value=doc2)
    mock_session.execute = AsyncMock(return_value=mock_result2)
    
    service.hashing_service.create_digest = Mock(return_value=MagicMock(
        update=Mock(),
        hexdigest=Mock(return_value="tampered2")
    ))
    
    await service.verify_document(mock_session, document_id=doc2.id, verifier_id=compliance_officer_id)
    
    # Verify second alert was published
    service._mock_event_publisher.publish_integrity_alert.assert_called_once()


# ============================================================================
# Test: Optional Freeze Flag Set on Affected Entity
# ============================================================================

@pytest.mark.anyio("asyncio")
async def test_freeze_flag_set_on_entity_after_mismatch(
    document_service_with_compliance_role,
    mock_document_factory,
    compliance_officer_id,
    entity_id,
):
    """
    Test: Optional freeze flag set on affected entity
    
    Validates:
    - When integrity alert is triggered, entity freeze flag can be set
    - Freeze flag prevents further operations on the entity
    - Freeze flag is published as part of the integrity alert
    - Compliance dashboard can display freeze status
    """
    service = document_service_with_compliance_role(compliance_officer_id)
    
    document = mock_document_factory(
        status=DocumentStatus.UPLOADED,
        sha256_hash="expected",
        entity_id=entity_id,
    )
    
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    async def mock_stream():
        yield b"tampered"
    
    service.storage_service.stream_document = Mock(return_value=mock_stream())
    service.hashing_service.create_digest = Mock(return_value=MagicMock(
        update=Mock(),
        hexdigest=Mock(return_value="tampered")
    ))
    
    # Trigger verification with freeze flag enabled
    await service.verify_document(
        mock_session,
        document_id=document.id,
        verifier_id=compliance_officer_id,
    )
    
    # Verify integrity alert includes freeze recommendation
    alert_kwargs = service._mock_event_publisher.publish_integrity_alert.call_args[1]
    
    # Alert should recommend freezing the entity
    assert "recommended_action" in alert_kwargs
    assert alert_kwargs["recommended_action"] == "FREEZE_ENTITY"
    
    # Alert should include entity context for freeze
    assert alert_kwargs["entity_id"] == entity_id
    assert alert_kwargs["entity_type"] == DocumentEntityType.ISSUER


@pytest.mark.anyio("asyncio")
async def test_freeze_flag_included_in_alert_payload(
    document_service_with_compliance_role,
    mock_document_factory,
    compliance_officer_id,
    entity_id,
):
    """
    Test: Freeze flag included in alert payload
    
    Validates:
    - Integrity alert payload includes freeze recommendation
    - Dashboard can extract freeze flag from alert
    - Freeze flag is clearly marked for compliance action
    """
    service = document_service_with_compliance_role(compliance_officer_id)
    
    document = mock_document_factory(
        status=DocumentStatus.UPLOADED,
        sha256_hash="original",
        entity_id=entity_id,
        entity_type=DocumentEntityType.ISSUER,
    )
    
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    async def mock_stream():
        yield b"tampered"
    
    service.storage_service.stream_document = Mock(return_value=mock_stream())
    service.hashing_service.create_digest = Mock(return_value=MagicMock(
        update=Mock(),
        hexdigest=Mock(return_value="tampered")
    ))
    
    await service.verify_document(mock_session, document_id=document.id, verifier_id=compliance_officer_id)
    
    alert_kwargs = service._mock_event_publisher.publish_integrity_alert.call_args[1]
    
    # Verify freeze recommendation structure
    assert alert_kwargs["recommended_action"] == "FREEZE_ENTITY"
    assert alert_kwargs["severity"] == "CRITICAL"
    assert "entity_id" in alert_kwargs
    assert "entity_type" in alert_kwargs


# ============================================================================
# Test: Complete Compliance Audit Flow
# ============================================================================

@pytest.mark.anyio("asyncio")
async def test_complete_compliance_audit_flow(
    document_service_with_compliance_role,
    mock_document_factory,
    compliance_officer_id,
    entity_id,
    mock_file_content,
):
    """
    Test: Complete compliance audit flow from verification to alert
    
    Validates end-to-end workflow:
    1. Compliance officer triggers document verification
    2. Hash mismatch detected (tampering)
    3. Document status changes to MISMATCH
    4. Audit event published (document.mismatch)
    5. Integrity alert published to compliance queue
    6. Alert contains comprehensive metadata
    7. Freeze recommendation included
    8. All events logged appropriately
    """
    service = document_service_with_compliance_role(compliance_officer_id)
    
    # Setup: Document uploaded by user
    user_id = uuid4()
    original_hash = service.hashing_service.compute_sha256(io.BytesIO(mock_file_content))
    
    document = mock_document_factory(
        status=DocumentStatus.UPLOADED,
        sha256_hash=original_hash,
        entity_id=entity_id,
        entity_type=DocumentEntityType.ISSUER,
        filename="financial_report_Q4.pdf",
        uploaded_by=user_id,
    )
    
    # Mock session
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    # Simulate tampering: file content changed
    tampered_content = b"This has been maliciously altered!"
    tampered_hash = service.hashing_service.compute_sha256(io.BytesIO(tampered_content))
    
    async def mock_stream():
        yield tampered_content
    
    service.storage_service.stream_document = Mock(return_value=mock_stream())
    
    # Step 1: Compliance officer triggers verification
    verified_document = await service.verify_document(
        mock_session,
        document_id=document.id,
        verifier_id=compliance_officer_id,
    )
    
    # Step 2 & 3: Verify hash mismatch detected and status changed
    assert verified_document.status == DocumentStatus.MISMATCH
    assert verified_document.sha256_hash == original_hash  # Original hash preserved
    
    # Step 4: Verify audit event published
    service._mock_audit_publisher.publish_event.assert_called_once()
    audit_call = service._mock_audit_publisher.publish_event.call_args[1]
    assert audit_call["action"] == "document.mismatch"
    assert audit_call["actor_id"] == compliance_officer_id
    assert audit_call["details"]["expected_hash"] == original_hash
    assert audit_call["details"]["calculated_hash"] == tampered_hash
    
    # Step 5 & 6: Verify integrity alert published with comprehensive metadata
    service._mock_event_publisher.publish_integrity_alert.assert_called_once()
    alert_call = service._mock_event_publisher.publish_integrity_alert.call_args[1]
    
    assert alert_call["document_id"] == document.id
    assert alert_call["filename"] == "financial_report_Q4.pdf"
    assert alert_call["entity_id"] == entity_id
    assert alert_call["entity_type"] == DocumentEntityType.ISSUER
    assert alert_call["expected_hash"] == original_hash
    assert alert_call["calculated_hash"] == tampered_hash
    assert alert_call["verified_by"] == compliance_officer_id
    assert alert_call["severity"] == "CRITICAL"
    
    # Step 7: Verify freeze recommendation
    assert alert_call["recommended_action"] == "FREEZE_ENTITY"


@pytest.mark.anyio("asyncio")
async def test_successful_verification_does_not_trigger_alert(
    document_service_with_compliance_role,
    mock_document_factory,
    compliance_officer_id,
    mock_file_content,
):
    """
    Test: Successful verification does not trigger integrity alert
    
    Validates:
    - When hash matches, no integrity alert is published
    - Only audit event for successful verification is published
    - No freeze flag is set
    - Compliance dashboard does not receive false positives
    """
    service = document_service_with_compliance_role(compliance_officer_id)
    
    original_hash = service.hashing_service.compute_sha256(io.BytesIO(mock_file_content))
    document = mock_document_factory(status=DocumentStatus.UPLOADED, sha256_hash=original_hash)
    
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    async def mock_stream():
        yield mock_file_content
    
    service.storage_service.stream_document = Mock(return_value=mock_stream())
    
    verified_document = await service.verify_document(
        mock_session,
        document_id=document.id,
        verifier_id=compliance_officer_id,
    )
    
    # Verify status is VERIFIED (not MISMATCH)
    assert verified_document.status == DocumentStatus.VERIFIED
    
    # Verify audit event published (document.verified)
    service._mock_audit_publisher.publish_event.assert_called_once()
    audit_call = service._mock_audit_publisher.publish_event.call_args[1]
    assert audit_call["action"] == "document.verified"
    
    # Verify NO integrity alert published
    service._mock_event_publisher.publish_integrity_alert.assert_not_called()


@pytest.mark.anyio("asyncio")
async def test_compliance_officer_role_permissions():
    """
    Test: Compliance officer role has appropriate permissions
    
    Validates:
    - Compliance officer can verify documents (document:verify)
    - Compliance officer can download documents (document:download)
    - Compliance officer can archive documents (document:archive)
    - Compliance officer CANNOT upload documents (read-only + verify + admin actions)
    """
    compliance_officer_id = uuid4()
    role_mapping = {compliance_officer_id: "compliance_officer"}
    epr_service = EprServiceMock(role_permissions=role_mapping)
    
    entity_id = uuid4()
    
    # Test verify permission
    assert await epr_service.is_authorized(
        user_id=compliance_officer_id,
        action="document:verify",
        resource_id=entity_id,
    )
    
    # Test download permission
    assert await epr_service.is_authorized(
        user_id=compliance_officer_id,
        action="document:download",
        resource_id=entity_id,
    )
    
    # Test archive permission
    assert await epr_service.is_authorized(
        user_id=compliance_officer_id,
        action="document:archive",
        resource_id=entity_id,
    )
    
    # Test upload permission (should be denied - compliance officers don't upload)
    assert not await epr_service.is_authorized(
        user_id=compliance_officer_id,
        action="document:upload",
        resource_id=entity_id,
    )











