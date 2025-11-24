from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest
from unittest.mock import AsyncMock, MagicMock

from app.models.document import DocumentEntityType, DocumentSignatureState, DocumentStatus
from app.schemas.document import DocumentSignatureRequest, DocumentSignerAssignment
from app.services.document_signature_service import DocumentSignatureService, SignatureOperationError


@pytest.mark.anyio("asyncio")
async def test_request_signatures_happy_path():
    document_service = MagicMock()
    document_service.storage_service = MagicMock()
    document_service.storage_service.download_document_bytes = AsyncMock(return_value=b"pdf-bytes")

    document = SimpleNamespace(
        id=uuid4(),
        status=DocumentStatus.UPLOADED,
        entity_type=DocumentEntityType.ISSUER,
        entity_id=uuid4(),
        filename="agreement.pdf",
        storage_key="documents/key",
        signatures_json=None,
        signature_state=None,
        signature_envelope_id=None,
    )
    document_service.get_document = AsyncMock(return_value=document)

    docusign_service = MagicMock()
    docusign_service.create_envelope = AsyncMock(return_value=("env-1", {"user@example.com": "1"}))

    user_directory = MagicMock()
    user_directory.get_user = AsyncMock(return_value={"id": str(uuid4()), "email": "user@example.com", "first_name": "Pat", "last_name": "Signer"})

    audit_publisher = MagicMock()
    audit_publisher.publish_event = AsyncMock()
    event_publisher = MagicMock()
    event_publisher.publish = AsyncMock()

    service = DocumentSignatureService(
        document_service=document_service,
        docusign_service=docusign_service,
        user_directory_service=user_directory,
        audit_event_publisher=audit_publisher,
        event_publisher=event_publisher,
    )

    payload = DocumentSignatureRequest(
        requested_by=uuid4(),
        signers=[DocumentSignerAssignment(user_id=uuid4(), email="user@example.com", role="issuer", routing_order=1)],
    )

    session = AsyncMock()
    result = await service.request_signatures(session, document_id=document.id, payload=payload, requested_by=payload.requested_by)

    assert result.signature_state == DocumentSignatureState.PENDING
    assert result.signature_envelope_id == "env-1"
    assert len(result.signatures_json) == 1
    audit_publisher.publish_event.assert_awaited_once()


@pytest.mark.anyio("asyncio")
async def test_request_signatures_raises_when_archived():
    document_service = MagicMock()
    document_service.storage_service = MagicMock()
    document = SimpleNamespace(
        id=uuid4(),
        status=DocumentStatus.ARCHIVED,
        entity_type=DocumentEntityType.ISSUER,
        entity_id=uuid4(),
        filename="agreement.pdf",
        storage_key="documents/key",
        signatures_json=None,
        signature_state=None,
    )
    document_service.get_document = AsyncMock(return_value=document)

    audit_publisher = MagicMock()
    audit_publisher.publish_event = AsyncMock()
    event_publisher = MagicMock()
    event_publisher.publish = AsyncMock()

    service = DocumentSignatureService(
        document_service=document_service,
        docusign_service=MagicMock(),
        user_directory_service=MagicMock(),
        audit_event_publisher=audit_publisher,
        event_publisher=event_publisher,
    )

    payload = DocumentSignatureRequest(
        requested_by=uuid4(),
        signers=[DocumentSignerAssignment(email="user@example.com")],
    )

    session = AsyncMock()
    with pytest.raises(SignatureOperationError):
        await service.request_signatures(session, document_id=document.id, payload=payload, requested_by=payload.requested_by)


@pytest.mark.anyio("asyncio")
async def test_process_webhook_updates_state():
    document_service = MagicMock()
    audit_publisher = MagicMock()
    audit_publisher.publish_event = AsyncMock()
    event_publisher = MagicMock()
    event_publisher.publish = AsyncMock()

    service = DocumentSignatureService(
        document_service=document_service,
        docusign_service=MagicMock(),
        user_directory_service=MagicMock(),
        audit_event_publisher=audit_publisher,
        event_publisher=event_publisher,
    )

    document = SimpleNamespace(
        id=uuid4(),
        signatures_json=[
            {
                "docusign_recipient_id": "1",
                "email": "user@example.com",
                "signed": False,
            }
        ],
        signature_state=DocumentSignatureState.PENDING,
    )

    session = AsyncMock()
    session.execute = AsyncMock()
    session.execute.return_value.scalar_one_or_none = lambda: document

    await service.process_webhook_notification(
        session,
        envelope_id="env-1",
        recipient_updates=[{"recipientId": "1", "status": "completed"}],
    )

    assert document.signature_state == DocumentSignatureState.COMPLETED
