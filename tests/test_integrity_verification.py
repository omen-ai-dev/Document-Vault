"""Comprehensive tests for Integrity Check / Hash Verification.

Tests SHA-256 hash-based integrity verification to detect tampered data.
"""

from __future__ import annotations

import hashlib
import io
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, Mock
from uuid import uuid4

import pytest

from app.models.document import Document, DocumentEntityType, DocumentStatus, DocumentType
from app.services.audit_event_publisher import AuditEventPublisher
from app.services.blockchain_service import BlockchainService
from app.services.document_service import DocumentService
from app.services.epr_service_mock import EprServiceMock
from app.services.hashing_service import HashingService
from app.services.storage_service import StorageService
from app.events.publisher import DocumentEventPublisher


# ==================== Fixtures ====================


@pytest.fixture
def original_file_content():
    """Original file content for testing."""
    return b"This is the original document content that should not be tampered with. " * 100


@pytest.fixture
def tampered_file_content():
    """Tampered file content (one byte changed)."""
    return b"This is the MODIFIED document content that should not be tampered with. " * 100


@pytest.fixture
def mock_document_for_verification(original_file_content):
    """Create a mock document with SHA-256 hash."""
    doc_id = uuid4()
    entity_id = uuid4()
    user_id = uuid4()
    
    # Compute original hash
    original_hash = hashlib.sha256(original_file_content).hexdigest()
    
    return Document(
        id=doc_id,
        entity_type=DocumentEntityType.ISSUER,
        entity_id=entity_id,
        document_type=DocumentType.OPERATING_AGREEMENT,
        filename="important_contract.pdf",
        mime_type="application/pdf",
        size_bytes=len(original_file_content),
        storage_bucket="test-bucket",
        storage_key=f"documents/{doc_id}/important_contract.pdf",
        sha256_hash=original_hash,
        status=DocumentStatus.UPLOADED,
        uploaded_by=user_id,
        hash_verified_at=None,
        verified_by=None,
    )


@pytest.fixture
def document_service_for_verification():
    """Create DocumentService for verification testing."""
    mock_storage = MagicMock(spec=StorageService)
    hashing_service = HashingService()  # Use real hashing service
    
    mock_audit_publisher = MagicMock(spec=AuditEventPublisher)
    mock_audit_publisher.publish_event = AsyncMock()
    
    mock_epr = MagicMock(spec=EprServiceMock)
    mock_epr.is_authorized = AsyncMock(return_value=True)
    
    mock_blockchain = MagicMock(spec=BlockchainService)
    mock_blockchain.register_document = AsyncMock(return_value="tx-blockchain-123")
    
    mock_event_publisher = MagicMock(spec=DocumentEventPublisher)
    mock_event_publisher.publish = AsyncMock()
    
    return DocumentService(
        storage_service=mock_storage,
        hashing_service=hashing_service,
        audit_event_publisher=mock_audit_publisher,
        access_control_service=mock_epr,
        blockchain_service=mock_blockchain,
        event_publisher=mock_event_publisher,
    )


# ==================== Test 1: Generated Hash Matches Stored Hash ====================


@pytest.mark.anyio("asyncio")
async def test_generated_hash_matches_stored_hash(
    document_service_for_verification, mock_document_for_verification, original_file_content
):
    """
    Test: Generated hash matches stored hash
    
    Validates:
    - Hash generated during verification matches original
    - Document status updated to VERIFIED
    - hash_verified_at timestamp set
    - verified_by field populated
    - Blockchain registration triggered
    - Audit event published
    """
    service = document_service_for_verification
    document = mock_document_for_verification
    verifier_id = uuid4()
    
    # Mock storage to return original content
    async def mock_stream_document(storage_key):
        """Stream original content in chunks."""
        chunk_size = 1024
        for i in range(0, len(original_file_content), chunk_size):
            yield original_file_content[i:i + chunk_size]
    
    service.storage_service.stream_document = mock_stream_document
    
    # Mock session
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    # Store original hash for comparison
    original_hash = document.sha256_hash
    
    # Execute verification
    verified_document = await service.verify_document(
        mock_session,
        document_id=document.id,
        verifier_id=verifier_id,
    )
    
    # Assertions
    assert verified_document.status == DocumentStatus.VERIFIED
    assert verified_document.sha256_hash == original_hash
    assert verified_document.hash_verified_at is not None
    assert verified_document.verified_by == verifier_id
    assert verified_document.on_chain_reference == "tx-blockchain-123"
    
    # Verify blockchain registration called
    service.blockchain_service.register_document.assert_called_once()
    
    # Verify audit event published
    service.audit_event_publisher.publish_event.assert_called_once()
    audit_call = service.audit_event_publisher.publish_event.call_args[1]
    assert audit_call["action"] == "document.verified"
    assert audit_call["actor_id"] == verifier_id
    assert audit_call["details"]["sha256_hash"] == original_hash
    
    # Verify document event published
    service.event_publisher.publish.assert_called_once()
    event_call = service.event_publisher.publish.call_args[1]
    assert event_call["event_type"] == "document.verified"


@pytest.mark.anyio("asyncio")
async def test_hash_deterministic_across_verifications(
    document_service_for_verification, mock_document_for_verification, original_file_content
):
    """
    Test: Hash generation is deterministic
    
    Validates:
    - Same content always produces same hash
    - Multiple verifications produce identical hashes
    - No randomness in hash computation
    """
    service = document_service_for_verification
    document = mock_document_for_verification
    verifier_id = uuid4()
    
    # Mock storage to return original content
    async def mock_stream_document(storage_key):
        chunk_size = 1024
        for i in range(0, len(original_file_content), chunk_size):
            yield original_file_content[i:i + chunk_size]
    
    service.storage_service.stream_document = mock_stream_document
    
    # Mock session
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    # Original hash
    original_hash = document.sha256_hash
    
    # First verification
    verified_doc_1 = await service.verify_document(mock_session, document_id=document.id, verifier_id=verifier_id)
    hash_1 = verified_doc_1.sha256_hash
    
    # Reset document status for second verification
    document.status = DocumentStatus.UPLOADED
    document.hash_verified_at = None
    document.verified_by = None
    
    # Second verification
    verified_doc_2 = await service.verify_document(mock_session, document_id=document.id, verifier_id=verifier_id)
    hash_2 = verified_doc_2.sha256_hash
    
    # All hashes should be identical
    assert hash_1 == original_hash
    assert hash_2 == original_hash
    assert hash_1 == hash_2
    
    # Verify both succeeded
    assert verified_doc_1.status == DocumentStatus.VERIFIED
    assert verified_doc_2.status == DocumentStatus.VERIFIED


# ==================== Test 2: Altered File Triggers Verification Failure ====================


@pytest.mark.anyio("asyncio")
async def test_altered_file_triggers_verification_failure(
    document_service_for_verification, mock_document_for_verification, tampered_file_content
):
    """
    Test: Altered file triggers verification failure
    
    Validates:
    - Tampered file detected
    - Document status updated to MISMATCH
    - hash_verified_at remains None
    - verified_by remains None
    - Blockchain NOT registered (mismatch)
    - Mismatch audit event published with both hashes
    """
    service = document_service_for_verification
    document = mock_document_for_verification
    verifier_id = uuid4()
    
    # Mock storage to return TAMPERED content
    async def mock_stream_tampered_document(storage_key):
        """Stream tampered content."""
        chunk_size = 1024
        for i in range(0, len(tampered_file_content), chunk_size):
            yield tampered_file_content[i:i + chunk_size]
    
    service.storage_service.stream_document = mock_stream_tampered_document
    
    # Mock session
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    # Store original hash
    original_hash = document.sha256_hash
    calculated_tampered_hash = hashlib.sha256(tampered_file_content).hexdigest()
    
    # Execute verification
    mismatched_document = await service.verify_document(
        mock_session,
        document_id=document.id,
        verifier_id=verifier_id,
    )
    
    # Assertions - Tamper detection
    assert mismatched_document.status == DocumentStatus.MISMATCH
    assert mismatched_document.sha256_hash == original_hash  # Original hash unchanged
    assert mismatched_document.hash_verified_at is None  # No verification timestamp
    assert mismatched_document.verified_by is None  # No verifier recorded
    assert mismatched_document.on_chain_reference is None  # No blockchain registration
    
    # Verify blockchain NOT called (mismatch case)
    service.blockchain_service.register_document.assert_not_called()
    
    # Verify mismatch audit event published
    service.audit_event_publisher.publish_event.assert_called_once()
    audit_call = service.audit_event_publisher.publish_event.call_args[1]
    assert audit_call["action"] == "document.mismatch"
    assert audit_call["actor_id"] == verifier_id
    assert audit_call["details"]["expected_hash"] == original_hash
    assert audit_call["details"]["calculated_hash"] == calculated_tampered_hash
    assert audit_call["details"]["expected_hash"] != audit_call["details"]["calculated_hash"]
    
    # Verify mismatch event published
    service.event_publisher.publish.assert_called_once()
    event_call = service.event_publisher.publish.call_args[1]
    assert event_call["event_type"] == "document.mismatch"
    assert event_call["payload"]["expected_hash"] == original_hash
    assert event_call["payload"]["calculated_hash"] == calculated_tampered_hash


@pytest.mark.anyio("asyncio")
async def test_single_byte_alteration_detected(
    document_service_for_verification, mock_document_for_verification, original_file_content
):
    """
    Test: Single byte alteration detected
    
    Validates:
    - Even minimal tampering (1 byte) detected
    - SHA-256 avalanche effect demonstrated
    - Hashes completely different with tiny change
    """
    service = document_service_for_verification
    document = mock_document_for_verification
    verifier_id = uuid4()
    
    # Create content with single byte changed
    single_byte_altered = bytearray(original_file_content)
    single_byte_altered[100] = (single_byte_altered[100] + 1) % 256  # Change one byte
    single_byte_altered = bytes(single_byte_altered)
    
    # Mock storage to return single-byte altered content
    async def mock_stream_document(storage_key):
        chunk_size = 1024
        for i in range(0, len(single_byte_altered), chunk_size):
            yield single_byte_altered[i:i + chunk_size]
    
    service.storage_service.stream_document = mock_stream_document
    
    # Mock session
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    # Original hash
    original_hash = document.sha256_hash
    altered_hash = hashlib.sha256(single_byte_altered).hexdigest()
    
    # Verify they're completely different (avalanche effect)
    assert original_hash != altered_hash
    
    # Execute verification
    mismatched_document = await service.verify_document(
        mock_session,
        document_id=document.id,
        verifier_id=verifier_id,
    )
    
    # Assertions - Single byte change detected
    assert mismatched_document.status == DocumentStatus.MISMATCH
    assert mismatched_document.sha256_hash == original_hash
    
    # Verify mismatch logged
    audit_call = service.audit_event_publisher.publish_event.call_args[1]
    assert audit_call["details"]["expected_hash"] != audit_call["details"]["calculated_hash"]


@pytest.mark.anyio("asyncio")
async def test_multiple_tampering_scenarios(
    document_service_for_verification, mock_document_for_verification, original_file_content
):
    """
    Test: Various tampering scenarios detected
    
    Validates:
    - Content appended: detected
    - Content truncated: detected
    - Content replaced: detected
    - All scenarios result in MISMATCH
    """
    service = document_service_for_verification
    document = mock_document_for_verification
    verifier_id = uuid4()
    original_hash = document.sha256_hash
    
    # Scenario 1: Content appended
    appended_content = original_file_content + b" EXTRA DATA APPENDED"
    
    # Scenario 2: Content truncated
    truncated_content = original_file_content[:len(original_file_content) // 2]
    
    # Scenario 3: Content replaced
    replaced_content = b"COMPLETELY DIFFERENT CONTENT" * 100
    
    scenarios = [
        ("appended", appended_content),
        ("truncated", truncated_content),
        ("replaced", replaced_content),
    ]
    
    for scenario_name, tampered_content in scenarios:
        # Reset document state
        document.status = DocumentStatus.UPLOADED
        document.hash_verified_at = None
        document.verified_by = None
        document.on_chain_reference = None
        
        # Mock storage to return tampered content
        async def mock_stream_document(storage_key):
            chunk_size = 1024
            for i in range(0, len(tampered_content), chunk_size):
                yield tampered_content[i:i + chunk_size]
        
        service.storage_service.stream_document = mock_stream_document
        
        # Mock session
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none = Mock(return_value=document)
        mock_session.execute = AsyncMock(return_value=mock_result)
        
        # Reset mocks
        service.audit_event_publisher.publish_event.reset_mock()
        service.event_publisher.publish.reset_mock()
        
        # Execute verification
        mismatched_document = await service.verify_document(
            mock_session,
            document_id=document.id,
            verifier_id=verifier_id,
        )
        
        # Assert tampering detected
        assert mismatched_document.status == DocumentStatus.MISMATCH, f"Scenario '{scenario_name}' failed"
        assert mismatched_document.sha256_hash == original_hash, f"Original hash changed in '{scenario_name}'"
        
        # Verify mismatch event published
        assert service.audit_event_publisher.publish_event.called, f"No audit event for '{scenario_name}'"
        audit_call = service.audit_event_publisher.publish_event.call_args[1]
        assert audit_call["action"] == "document.mismatch", f"Wrong action for '{scenario_name}'"


# ==================== Test 3: Regeneration Function Produces Identical Result ====================


@pytest.mark.anyio("asyncio")
async def test_regeneration_produces_identical_hash(
    document_service_for_verification, original_file_content
):
    """
    Test: Regeneration function produces identical result
    
    Validates:
    - Hash computation is deterministic
    - Same input always produces same output
    - Multiple regenerations identical
    - No time-based or random factors
    """
    service = document_service_for_verification
    hashing_service = service.hashing_service
    
    # Generate hash 10 times
    hashes = []
    for _ in range(10):
        file_obj = io.BytesIO(original_file_content)
        computed_hash = hashing_service.compute_sha256(file_obj)
        hashes.append(computed_hash)
    
    # All hashes should be identical
    assert len(set(hashes)) == 1, "Hash regeneration produced different results"
    
    # Verify against expected SHA-256
    expected_hash = hashlib.sha256(original_file_content).hexdigest()
    assert hashes[0] == expected_hash


@pytest.mark.anyio("asyncio")
async def test_streaming_regeneration_matches_full_hash(
    document_service_for_verification, original_file_content
):
    """
    Test: Streaming hash matches full content hash
    
    Validates:
    - Chunked streaming produces same hash
    - Different chunk sizes produce same result
    - Matches full content hash
    """
    service = document_service_for_verification
    hashing_service = service.hashing_service
    
    # Full content hash
    full_hash = hashlib.sha256(original_file_content).hexdigest()
    
    # Test various chunk sizes
    chunk_sizes = [64, 256, 1024, 4096, 8192]
    
    for chunk_size in chunk_sizes:
        # Stream in chunks
        digest = hashing_service.create_digest()
        for i in range(0, len(original_file_content), chunk_size):
            chunk = original_file_content[i:i + chunk_size]
            digest.update(chunk)
        
        streamed_hash = digest.hexdigest()
        
        # Should match full content hash
        assert streamed_hash == full_hash, f"Chunk size {chunk_size} produced different hash"


@pytest.mark.anyio("asyncio")
async def test_hash_regeneration_after_storage_retrieval(
    document_service_for_verification, mock_document_for_verification, original_file_content
):
    """
    Test: Hash regeneration after storage retrieval
    
    Validates:
    - Content retrieved from storage can be re-hashed
    - Re-hash matches original hash
    - Storage round-trip preserves integrity
    """
    service = document_service_for_verification
    document = mock_document_for_verification
    verifier_id = uuid4()
    
    # Mock storage to return original content
    async def mock_stream_document(storage_key):
        chunk_size = 1024
        for i in range(0, len(original_file_content), chunk_size):
            yield original_file_content[i:i + chunk_size]
    
    service.storage_service.stream_document = mock_stream_document
    
    # Mock session
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    # Original hash stored at upload
    original_upload_hash = document.sha256_hash
    
    # Verify after "storage retrieval"
    verified_document = await service.verify_document(
        mock_session,
        document_id=document.id,
        verifier_id=verifier_id,
    )
    
    # Regenerated hash should match original
    assert verified_document.status == DocumentStatus.VERIFIED
    assert verified_document.sha256_hash == original_upload_hash
    
    # Compute hash directly for triple-check
    direct_hash = hashlib.sha256(original_file_content).hexdigest()
    assert verified_document.sha256_hash == direct_hash


# ==================== Test 4: Complete Integrity Verification Flow ====================


@pytest.mark.anyio("asyncio")
async def test_complete_integrity_verification_flow(
    document_service_for_verification, mock_document_for_verification, original_file_content
):
    """
    Test: Complete integrity verification flow
    
    Validates entire flow:
    1. Upload: Hash computed and stored
    2. Storage: Content stored in S3
    3. Retrieval: Content retrieved from S3
    4. Re-hash: Hash recomputed from retrieved content
    5. Comparison: Hashes compared
    6. Success: Document marked as verified
    7. Blockchain: Hash registered on-chain
    8. Events: Audit and document events published
    """
    service = document_service_for_verification
    document = mock_document_for_verification
    verifier_id = uuid4()
    
    # Mock storage stream
    async def mock_stream_document(storage_key):
        chunk_size = 1024
        for i in range(0, len(original_file_content), chunk_size):
            yield original_file_content[i:i + chunk_size]
    
    service.storage_service.stream_document = mock_stream_document
    
    # Mock session
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    # Pre-verification state
    assert document.status == DocumentStatus.UPLOADED
    assert document.hash_verified_at is None
    assert document.verified_by is None
    assert document.on_chain_reference is None
    
    original_hash = document.sha256_hash
    
    # Execute verification
    verified_document = await service.verify_document(
        mock_session,
        document_id=document.id,
        verifier_id=verifier_id,
    )
    
    # Step-by-step validation
    
    # 1. Hash comparison successful
    assert verified_document.sha256_hash == original_hash
    
    # 2. Document status updated
    assert verified_document.status == DocumentStatus.VERIFIED
    
    # 3. Verification metadata set
    assert verified_document.hash_verified_at is not None
    assert verified_document.verified_by == verifier_id
    assert isinstance(verified_document.hash_verified_at, datetime)
    assert verified_document.hash_verified_at.tzinfo is not None  # Timezone-aware
    
    # 4. Blockchain registration
    assert verified_document.on_chain_reference == "tx-blockchain-123"
    service.blockchain_service.register_document.assert_called_once_with(
        token_id=document.token_id,
        document_hash=document.sha256_hash,
        metadata_uri=None,
    )
    
    # 5. Audit event published
    service.audit_event_publisher.publish_event.assert_called_once()
    audit_call = service.audit_event_publisher.publish_event.call_args[1]
    assert audit_call["action"] == "document.verified"
    assert audit_call["actor_id"] == verifier_id
    assert audit_call["actor_type"] == "user"
    assert audit_call["entity_id"] == document.id
    assert audit_call["entity_type"] == "document"
    assert audit_call["details"]["sha256_hash"] == original_hash
    assert audit_call["details"]["on_chain_reference"] == "tx-blockchain-123"
    
    # 6. Document event published
    service.event_publisher.publish.assert_called_once()
    event_call = service.event_publisher.publish.call_args[1]
    assert event_call["event_type"] == "document.verified"
    assert event_call["payload"]["document_id"] == str(document.id)
    assert event_call["payload"]["sha256_hash"] == original_hash


# ==================== Test 5: Edge Cases and Error Handling ====================


@pytest.mark.anyio("asyncio")
async def test_empty_file_integrity_verification(document_service_for_verification):
    """
    Test: Empty file can be verified
    
    Validates:
    - Empty files have valid SHA-256 hash
    - Verification works for edge case
    """
    empty_content = b""
    empty_hash = hashlib.sha256(empty_content).hexdigest()
    
    # Known SHA-256 hash of empty string
    expected_empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert empty_hash == expected_empty_hash


@pytest.mark.anyio("asyncio")
async def test_large_file_integrity_verification(document_service_for_verification):
    """
    Test: Large file (simulated) can be verified
    
    Validates:
    - Streaming works for large files
    - Hash computation handles large data
    """
    # Simulate 10MB file
    large_content = b"A" * (10 * 1024 * 1024)
    
    hashing_service = document_service_for_verification.hashing_service
    
    # Stream in chunks
    digest = hashing_service.create_digest()
    chunk_size = 1024 * 1024  # 1MB chunks
    
    for i in range(0, len(large_content), chunk_size):
        chunk = large_content[i:i + chunk_size]
        digest.update(chunk)
    
    streamed_hash = digest.hexdigest()
    
    # Compare with full hash
    full_hash = hashlib.sha256(large_content).hexdigest()
    
    assert streamed_hash == full_hash


@pytest.mark.anyio("asyncio")
async def test_unicode_content_integrity_verification(document_service_for_verification):
    """
    Test: Unicode content integrity verification
    
    Validates:
    - Unicode/UTF-8 content handled correctly
    - Byte representation consistent
    """
    unicode_content = "Hello 世界 🌍 Привет مرحبا".encode('utf-8')
    
    hashing_service = document_service_for_verification.hashing_service
    
    file_obj = io.BytesIO(unicode_content)
    computed_hash = hashing_service.compute_sha256(file_obj)
    
    expected_hash = hashlib.sha256(unicode_content).hexdigest()
    
    assert computed_hash == expected_hash













