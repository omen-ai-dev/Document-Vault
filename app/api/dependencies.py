from __future__ import annotations
from functools import lru_cache
import httpx

from app.core.config import settings
from app.events.publisher import DocumentEventPublisher
from app.services.audit_event_publisher import AuditEventPublisher
from app.services.blockchain_service import BlockchainService
from app.services.document_service import DocumentService
from app.services.document_signature_service import DocumentSignatureService
from app.services.docusign_service import DocuSignService
from app.services.epr_service import EprService
from app.services.epr_service_mock import EprServiceMock
from app.services.hashing_service import HashingService
from app.services.storage_service import StorageService
from app.services.user_directory_service import UserDirectoryService


@lru_cache(maxsize=1)
def get_http_client() -> httpx.AsyncClient:
    return httpx.AsyncClient()


@lru_cache(maxsize=1)
def get_access_control_service(
    http_client: httpx.AsyncClient = get_http_client(),
) -> EprService | EprServiceMock:
    if settings.epr_mock_mode:
        return EprServiceMock()
    return EprService(http_client)


@lru_cache(maxsize=1)
def get_document_service() -> DocumentService:
    http_client = get_http_client()
    return DocumentService(
        storage_service=StorageService(),
        hashing_service=HashingService(),
        audit_event_publisher=AuditEventPublisher(http_client),
        access_control_service=get_access_control_service(http_client),
        blockchain_service=BlockchainService(),
        event_publisher=DocumentEventPublisher(),
    )


@lru_cache(maxsize=1)
def get_user_directory_service(http_client: httpx.AsyncClient = get_http_client()) -> UserDirectoryService:
    return UserDirectoryService(http_client)


@lru_cache(maxsize=1)
def get_docusign_service() -> DocuSignService:
    return DocuSignService()


@lru_cache(maxsize=1)
def get_document_signature_service() -> DocumentSignatureService:
    document_service = get_document_service()
    return DocumentSignatureService(
        document_service=document_service,
        docusign_service=get_docusign_service(),
        user_directory_service=get_user_directory_service(),
        audit_event_publisher=document_service.audit_event_publisher,
        event_publisher=document_service.event_publisher,
    )
